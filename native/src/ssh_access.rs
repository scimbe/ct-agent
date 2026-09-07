//! `ct-agent ssh` / `ct-agent ssh-config` (scimbe/ct-agent#204): SSH through the tunnel, configured
//! in `~/.ssh/config` the way cloudflared's `access ssh` is.
//!
//! WHY SSH-over-TLS rather than a new wire protocol: the tunnel's public front door is an
//! SNI-routed TLS listener (`:443`), and in Grün the client's TLS session reaches the Agent
//! byte-for-byte. So an OpenSSH `ProxyCommand` that opens a TLS connection to `<hostname>:443`
//! and pipes ssh's stdin/stdout through it needs nothing new on the Edge at all -- the Agent
//! terminates that TLS with the hostname's own ACME certificate (`CT_AGENT_ORIGIN_TLS=terminate`,
//! see `config::OriginTls`) and forwards the SSH plaintext to the local sshd. The user types
//! `ssh <hostname>`; the stanza `ssh-config` prints is what makes ssh call this ProxyCommand.
//!
//! Everything that decides -- argument parsing, the stanza text, the TLS client config -- is a
//! pure function; the byte pump ([`pipe_over_tls`]) is generic over its three streams so the
//! tests drive it with in-memory duplexes and a loopback TLS echo server, never a real ssh.
//! `run_ssh` is the thin wrapper that plugs in the process's stdin/stdout and a real TCP dial.
//!
//! stdout is the SSH byte stream: NOTHING in this module may print to stdout except the pump
//! itself (and `ssh-config`, whose whole output is the stanza). Diagnostics go to stderr,
//! prefixed `ct-agent ssh:`, where ssh relays them to the user.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Usage of the two subcommands, printed on stderr above any argument error (#239 discipline:
/// a typo fails loudly, and the message says what would have been accepted).
pub const SSH_USAGE: &str = "\
usage: ct-agent ssh <hostname> [--port <n>] [--ca <pem-file>] [--connect-timeout <secs>]
       ct-agent ssh-config <hostname> [--user <name>] [--port <n>] [--ca <pem-file>]

  ssh          OpenSSH ProxyCommand: open TLS to <hostname>:<port> (default 443, SNI = hostname)
               and pipe ssh's stdin/stdout through it. Trusts the system's public roots plus every
               certificate in --ca (PEM). Never run by hand -- ssh runs it via ProxyCommand.
  ssh-config   Print the ~/.ssh/config stanza that makes `ssh <hostname>` use it.
";

/// The default TLS port: the tunnel's SNI-routed front door.
pub const DEFAULT_PORT: u16 = 443;
/// Default bound on the TCP connect (DNS + SYN). Same 10 s as `transport::TCP_TLS_CONNECT_TIMEOUT`:
/// this dial crosses the internet to the Edge, and ssh's own ConnectTimeout does not cover a
/// ProxyCommand, so without one an unroutable Edge would hang `ssh` indefinitely.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The stderr prefix every diagnostic carries, so it is attributable inside ssh's own output.
pub const STDERR_PREFIX: &str = "ct-agent ssh:";

/// Parsed `ct-agent ssh` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshArgs {
    /// The tunnel hostname: both the SNI and, unless `connect` overrides it, the dial target.
    pub hostname: String,
    /// TLS port at the Edge.
    pub port: u16,
    /// Extra trust anchors (PEM, possibly several certificates) -- a private CA in a lab.
    pub ca: Option<PathBuf>,
    /// Bound on the TCP connect.
    pub connect_timeout: Duration,
    /// Test/diagnostic only (`--connect <ip:port>`): dial this address instead of resolving
    /// `hostname:port`, keeping `hostname` as the SNI. The end-to-end test needs the SNI to
    /// match the leaf's SAN while the TCP target is a loopback listener; an operator can use it
    /// to bypass a stale DNS entry. Deliberately not in [`SSH_USAGE`].
    pub connect: Option<SocketAddr>,
}

/// Parsed `ct-agent ssh-config` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshConfigArgs {
    /// The `Host` pattern and the ProxyCommand's hostname.
    pub hostname: String,
    /// `User` line, when given.
    pub user: Option<String>,
    /// `--port` on the ProxyCommand line, when given (443 is the default and is omitted).
    pub port: Option<u16>,
    /// `--ca` on the ProxyCommand line, when given.
    pub ca: Option<PathBuf>,
}

/// Reject a hostname that cannot be an SNI. rustls accepts IP literals as a `ServerName` too,
/// but the Edge routes on the DNS name and the certificate carries the DNS name, so an IP here
/// would only ever produce a confusing handshake failure later.
fn validate_sni_hostname(hostname: &str) -> Result<(), String> {
    match ServerName::try_from(hostname) {
        Ok(ServerName::DnsName(_)) => Ok(()),
        _ => Err(format!("'{hostname}' is not a valid DNS hostname (it is used as the TLS server name)")),
    }
}

/// The one flag-value reader both parsers share: `--flag <value>`, value required.
fn take_value<'a>(flag: &str, it: &mut impl Iterator<Item = &'a String>) -> Result<&'a String, String> {
    it.next().ok_or_else(|| format!("{flag} requires a value"))
}

fn parse_port(raw: &str) -> Result<u16, String> {
    match raw.trim().parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("invalid --port '{raw}' (expected 1..=65535)")),
        Ok(p) => Ok(p),
    }
}

/// Parse `ct-agent ssh`'s arguments (everything after `ssh`). Pure. Flags may come before or
/// after the hostname (ssh's `%h` substitution puts it wherever the stanza does); exactly one
/// positional argument is the hostname; an unknown flag or a second positional is an error.
pub fn parse_ssh_args(args: &[String]) -> Result<SshArgs, String> {
    let mut hostname: Option<String> = None;
    let mut port = DEFAULT_PORT;
    let mut ca = None;
    let mut connect_timeout = DEFAULT_CONNECT_TIMEOUT;
    let mut connect = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--port" => port = parse_port(take_value("--port", &mut it)?)?,
            "--ca" => ca = Some(PathBuf::from(take_value("--ca", &mut it)?)),
            "--connect-timeout" => {
                let raw = take_value("--connect-timeout", &mut it)?;
                connect_timeout = match raw.trim().parse::<u64>() {
                    Ok(0) | Err(_) => return Err(format!("invalid --connect-timeout '{raw}' (expected seconds >= 1)")),
                    Ok(secs) => Duration::from_secs(secs),
                };
            }
            "--connect" => {
                let raw = take_value("--connect", &mut it)?;
                connect = Some(
                    raw.trim()
                        .parse::<SocketAddr>()
                        .map_err(|e| format!("invalid --connect '{raw}' (expected ip:port): {e}"))?,
                );
            }
            other if other.starts_with('-') => return Err(format!("unrecognized argument '{other}'")),
            other => {
                if hostname.is_some() {
                    return Err(format!("unexpected extra argument '{other}' (only one hostname)"));
                }
                hostname = Some(other.to_string());
            }
        }
    }
    let hostname = hostname.ok_or_else(|| "missing <hostname>".to_string())?;
    validate_sni_hostname(&hostname)?;
    Ok(SshArgs { hostname, port, ca, connect_timeout, connect })
}

/// Parse `ct-agent ssh-config`'s arguments (everything after `ssh-config`). Pure; same
/// discipline as [`parse_ssh_args`].
pub fn parse_ssh_config_args(args: &[String]) -> Result<SshConfigArgs, String> {
    let mut hostname: Option<String> = None;
    let mut user = None;
    let mut port = None;
    let mut ca = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--user" => {
                let raw = take_value("--user", &mut it)?;
                if raw.trim().is_empty() || raw.chars().any(char::is_whitespace) {
                    return Err(format!("invalid --user '{raw}' (one word, no whitespace)"));
                }
                user = Some(raw.to_string());
            }
            "--port" => port = Some(parse_port(take_value("--port", &mut it)?)?),
            "--ca" => ca = Some(PathBuf::from(take_value("--ca", &mut it)?)),
            other if other.starts_with('-') => return Err(format!("unrecognized argument '{other}'")),
            other => {
                if hostname.is_some() {
                    return Err(format!("unexpected extra argument '{other}' (only one hostname)"));
                }
                hostname = Some(other.to_string());
            }
        }
    }
    let hostname = hostname.ok_or_else(|| "missing <hostname>".to_string())?;
    validate_sni_hostname(&hostname)?;
    Ok(SshConfigArgs { hostname, user, port, ca })
}

/// A path as it goes on the ProxyCommand line: double-quoted when it contains whitespace
/// (ssh_config splits the command on whitespace and honours double quotes), verbatim otherwise
/// so the common case reads exactly like the user typed it.
fn shell_word(path: &Path) -> String {
    let s = path.display().to_string();
    if s.chars().any(char::is_whitespace) {
        format!("\"{s}\"")
    } else {
        s
    }
}

/// The `~/.ssh/config` stanza for `args`, exactly:
///
/// ```text
/// # ct-agent ssh: SSH over TLS through the CADS tunnel (scimbe/ct-agent#204)
/// Host <hostname>
///   ProxyCommand ct-agent ssh <hostname> [--port <n>] [--ca <pem-file>]
///   User <name>
/// ```
///
/// The literal hostname rather than ssh's `%h`, like cloudflared: one stanza per host is what
/// an operator can read back and delete later, and it keeps a wildcard `Host` from ever routing
/// an unrelated name through the tunnel.
pub fn render_ssh_config(args: &SshConfigArgs) -> String {
    let mut proxy = format!("ct-agent ssh {}", args.hostname);
    if let Some(p) = args.port {
        proxy.push_str(&format!(" --port {p}"));
    }
    if let Some(ca) = &args.ca {
        proxy.push_str(&format!(" --ca {}", shell_word(ca)));
    }
    let mut out = String::new();
    out.push_str("# ct-agent ssh: SSH over TLS through the CADS tunnel (scimbe/ct-agent#204)\n");
    out.push_str(&format!("Host {}\n", args.hostname));
    out.push_str(&format!("  ProxyCommand {proxy}\n"));
    if let Some(user) = &args.user {
        out.push_str(&format!("  User {user}\n"));
    }
    out
}

/// The TLS client config: TLS 1.3/1.2, no ALPN (the Edge routes on SNI alone; an ALPN would
/// only give a future Edge something to refuse), root store = the Mozilla bundle (webpki-roots,
/// the same trust the browser plane relies on -- the hostname's certificate is a real Let's
/// Encrypt one) plus every certificate in `ca` when given (a lab CA; several may share one PEM
/// file). Errors name the file.
pub fn build_client_config(ca: Option<&Path>) -> Result<Arc<rustls::ClientConfig>, String> {
    use rustls::pki_types::pem::PemObject;
    crate::transport::install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca {
        let mut added = 0usize;
        let certs = CertificateDer::pem_file_iter(path).map_err(|e| format!("--ca {}: {e}", path.display()))?;
        for cert in certs {
            let cert = cert.map_err(|e| format!("--ca {}: {e}", path.display()))?;
            roots
                .add(cert)
                .map_err(|e| format!("--ca {}: not a usable CA certificate: {e}", path.display()))?;
            added += 1;
        }
        if added == 0 {
            return Err(format!("--ca {}: no certificate found in the file", path.display()));
        }
    }
    let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    Ok(Arc::new(config))
}

/// An EOF the far side produced by closing TCP without a TLS close_notify. rustls reports it as
/// `UnexpectedEof`; for this pump it is the normal end of a session (sshd closes the socket, the
/// Agent's relay ends, the TLS record layer never got to say goodbye), not a failure worth an
/// exit code -- ssh has its own integrity protection and its own idea of a clean disconnect.
fn is_truncated_close(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::UnexpectedEof
}

/// The core of `ct-agent ssh`: TLS-handshake over `transport` (SNI = `hostname`, trust = `tls`),
/// then pump `client_in` -> TLS and TLS -> `client_out` until either side ends. On `client_in`
/// EOF (ssh closed our stdin) the TLS write half is shut down cleanly (close_notify) and the
/// pump drains what the server still has to say, bounded; on TLS EOF (the server/sshd closed)
/// it returns so the process exits and ssh sees EOF. Generic over the three streams so the
/// tests run it over `tokio::io::duplex` pairs. `Ok(())` means a clean end; `Err` carries a
/// message already fit for stderr (no prefix).
pub async fn pipe_over_tls<R, W, S>(
    mut client_in: R,
    mut client_out: W,
    transport: S,
    hostname: &str,
    tls: Arc<rustls::ClientConfig>,
) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let server_name = ServerName::try_from(hostname)
        .map_err(|e| format!("'{hostname}' is not a valid TLS server name: {e}"))?
        .to_owned();
    let connector = tokio_rustls::TlsConnector::from(tls);
    let stream = connector
        .connect(server_name, transport)
        .await
        .map_err(|e| format!("TLS handshake with {hostname} failed: {e}"))?;
    let (mut tls_rd, mut tls_wr) = tokio::io::split(stream);

    let upstream = async {
        let copied = tokio::io::copy(&mut client_in, &mut tls_wr).await;
        // Whatever ended the copy, tell the server we are done writing (close_notify).
        let _ = tls_wr.shutdown().await;
        copied.map(|_| ()).map_err(|e| format!("stdin -> {hostname}: {e}"))
    };
    let downstream = async {
        let copied = tokio::io::copy(&mut tls_rd, &mut client_out).await;
        let _ = client_out.flush().await;
        match copied {
            Ok(_) => Ok(()),
            Err(e) if is_truncated_close(&e) => Ok(()),
            Err(e) => Err(format!("{hostname} -> stdout: {e}")),
        }
    };
    tokio::pin!(upstream);
    tokio::pin!(downstream);
    tokio::select! {
        up = &mut upstream => {
            up?;
            // Our side is done; give the server a bounded moment to finish what it was saying
            // (ssh's disconnect exchange), then leave -- never hang after ssh itself has gone.
            match tokio::time::timeout(Duration::from_secs(5), &mut downstream).await {
                Ok(down) => down,
                Err(_) => Ok(()),
            }
        }
        down = &mut downstream => {
            // The server ended the session: ssh needs to see EOF now. The upstream copy is
            // dropped mid-flight on purpose; nothing it could still send matters.
            down
        }
    }
}

/// Resolve and dial the TLS endpoint for `args`, bounded by its connect timeout. `--connect`
/// short-circuits the resolution (see [`SshArgs::connect`]).
pub async fn dial(args: &SshArgs) -> Result<TcpStream, String> {
    let target = match args.connect {
        Some(addr) => addr.to_string(),
        None => format!("{}:{}", args.hostname, args.port),
    };
    let tcp = tokio::time::timeout(args.connect_timeout, TcpStream::connect(target.as_str()))
        .await
        .map_err(|_| format!("connect to {target} timed out after {:?}", args.connect_timeout))?
        .map_err(|e| format!("connect to {target} failed: {e}"))?;
    // Interactive traffic: no Nagle delay on keystrokes, and the same keepalive posture as the
    // Agent's own long-lived Edge connections so an idle shell survives a NAT/middlebox timeout.
    let _ = tcp.set_nodelay(true);
    crate::transport::apply_tcp_keepalive(&tcp);
    Ok(tcp)
}

/// `ct-agent ssh`: the ProxyCommand body -- build the trust store, dial, and pump the
/// process's stdin/stdout through the TLS session. Returns the message for stderr on failure;
/// the caller prefixes it and exits 1.
pub async fn run_ssh(args: &SshArgs) -> Result<(), String> {
    let tls = build_client_config(args.ca.as_deref())?;
    let tcp = dial(args).await?;
    pipe_over_tls(tokio::io::stdin(), tokio::io::stdout(), tcp, &args.hostname, tls).await
}

/// Test-only PKI: a fresh rcgen CA plus a leaf for one hostname, as the PEM/DER pieces the
/// terminator, the `--ca` flag and a `RootCertStore` each want. Shared by this module's tests
/// and `serve.rs`'s terminator tests so the two halves of #204 are proven against the same
/// certificate shape. The integration test under `native/tests` carries its own copy (it cannot
/// see `cfg(test)` items).
#[cfg(test)]
pub(crate) mod test_pki {
    use rustls::pki_types::CertificateDer;

    /// One issued CA + leaf pair.
    pub(crate) struct TestPki {
        /// The CA certificate, PEM (what `--ca` reads).
        pub(crate) ca_pem: String,
        /// The CA certificate, DER (for a `RootCertStore`).
        pub(crate) ca_der: CertificateDer<'static>,
        /// The leaf certificate, PEM -- the "fullchain.pem" the terminator serves.
        pub(crate) leaf_pem: String,
        /// The leaf's private key, PEM (PKCS#8) -- the "privkey.pem".
        pub(crate) key_pem: String,
    }

    /// Issue a CA and a leaf whose only SAN is `host`.
    pub(crate) fn issue(host: &str) -> TestPki {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, "ct-agent test CA");
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec![host.to_string()]).unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        TestPki {
            ca_pem: ca_cert.pem(),
            ca_der: ca_cert.der().clone(),
            leaf_pem: leaf.pem(),
            key_pem: leaf_key.serialize_pem(),
        }
    }

    /// Write the pair to `dir` as `ca.pem`, `fullchain.pem`, `privkey.pem`; returns the three paths.
    pub(crate) fn write_to(
        pki: &TestPki,
        dir: &std::path::Path,
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let ca = dir.join("ca.pem");
        let cert = dir.join("fullchain.pem");
        let key = dir.join("privkey.pem");
        std::fs::write(&ca, &pki.ca_pem).unwrap();
        std::fs::write(&cert, &pki.leaf_pem).unwrap();
        std::fs::write(&key, &pki.key_pem).unwrap();
        (ca, cert, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivateKeyDer;
    use tokio::io::AsyncReadExt;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    // ---- parse_ssh_args ----

    #[test]
    fn ssh_args_hostname_alone_takes_every_default() {
        let a = parse_ssh_args(&args(&["ssh.example.org"])).unwrap();
        assert_eq!(
            a,
            SshArgs {
                hostname: "ssh.example.org".into(),
                port: 443,
                ca: None,
                connect_timeout: Duration::from_secs(10),
                connect: None,
            }
        );
    }

    #[test]
    fn ssh_args_reads_each_flag_before_or_after_the_hostname() {
        let a = parse_ssh_args(&args(&[
            "--port",
            "8443",
            "ssh.example.org",
            "--ca",
            "/tmp/ca.pem",
            "--connect-timeout",
            "3",
            "--connect",
            "127.0.0.1:9",
        ]))
        .unwrap();
        assert_eq!(a.hostname, "ssh.example.org");
        assert_eq!(a.port, 8443);
        assert_eq!(a.ca.as_deref(), Some(Path::new("/tmp/ca.pem")));
        assert_eq!(a.connect_timeout, Duration::from_secs(3));
        assert_eq!(a.connect, Some("127.0.0.1:9".parse().unwrap()));
    }

    #[test]
    fn ssh_args_missing_hostname_is_an_error() {
        let err = parse_ssh_args(&args(&[])).unwrap_err();
        assert!(err.contains("missing <hostname>"), "{err}");
        let err = parse_ssh_args(&args(&["--port", "443"])).unwrap_err();
        assert!(err.contains("missing <hostname>"), "{err}");
    }

    #[test]
    fn ssh_args_rejects_a_bad_port() {
        for bad in ["0", "70000", "abc", ""] {
            let err = parse_ssh_args(&args(&["h.example.org", "--port", bad])).unwrap_err();
            assert!(err.contains("invalid --port"), "{bad}: {err}");
        }
        let err = parse_ssh_args(&args(&["h.example.org", "--port"])).unwrap_err();
        assert!(err.contains("--port requires a value"), "{err}");
    }

    #[test]
    fn ssh_args_rejects_unknown_flags_and_extra_positionals() {
        // #239 discipline: a misspelt flag must not be silently ignored.
        let err = parse_ssh_args(&args(&["h.example.org", "--prot", "443"])).unwrap_err();
        assert!(err.contains("unrecognized argument '--prot'"), "{err}");
        let err = parse_ssh_args(&args(&["h.example.org", "other.example.org"])).unwrap_err();
        assert!(err.contains("unexpected extra argument"), "{err}");
    }

    #[test]
    fn ssh_args_rejects_a_hostname_that_is_not_a_dns_name() {
        // An IP literal is a valid rustls ServerName but not an SNI the Edge can route on.
        let err = parse_ssh_args(&args(&["10.0.0.1"])).unwrap_err();
        assert!(err.contains("not a valid DNS hostname"), "{err}");
        let err = parse_ssh_args(&args(&["not a host"])).unwrap_err();
        assert!(err.contains("not a valid DNS hostname"), "{err}");
    }

    #[test]
    fn ssh_args_rejects_bad_timeouts_and_connect_overrides() {
        let err = parse_ssh_args(&args(&["h.example.org", "--connect-timeout", "0"])).unwrap_err();
        assert!(err.contains("invalid --connect-timeout"), "{err}");
        let err = parse_ssh_args(&args(&["h.example.org", "--connect", "nope"])).unwrap_err();
        assert!(err.contains("invalid --connect"), "{err}");
    }

    // ---- parse_ssh_config_args + render ----

    #[test]
    fn ssh_config_renders_the_minimal_stanza_exactly() {
        let a = parse_ssh_config_args(&args(&["ssh.example.org"])).unwrap();
        assert_eq!(
            render_ssh_config(&a),
            "# ct-agent ssh: SSH over TLS through the CADS tunnel (scimbe/ct-agent#204)\n\
             Host ssh.example.org\n\
             \x20 ProxyCommand ct-agent ssh ssh.example.org\n"
        );
    }

    #[test]
    fn ssh_config_renders_every_optional_line_exactly() {
        let a = parse_ssh_config_args(&args(&[
            "ssh.example.org",
            "--user",
            "alice",
            "--port",
            "8443",
            "--ca",
            "/etc/ct/ca.pem",
        ]))
        .unwrap();
        assert_eq!(
            render_ssh_config(&a),
            "# ct-agent ssh: SSH over TLS through the CADS tunnel (scimbe/ct-agent#204)\n\
             Host ssh.example.org\n\
             \x20 ProxyCommand ct-agent ssh ssh.example.org --port 8443 --ca /etc/ct/ca.pem\n\
             \x20 User alice\n"
        );
    }

    #[test]
    fn ssh_config_quotes_a_ca_path_with_whitespace() {
        let a = SshConfigArgs {
            hostname: "h.example.org".into(),
            user: None,
            port: None,
            ca: Some(PathBuf::from("/my certs/ca.pem")),
        };
        assert!(render_ssh_config(&a).contains("--ca \"/my certs/ca.pem\"\n"));
    }

    #[test]
    fn ssh_config_rejects_unknown_flags_bad_users_and_missing_hostname() {
        let err = parse_ssh_config_args(&args(&["h.example.org", "--usr", "x"])).unwrap_err();
        assert!(err.contains("unrecognized argument '--usr'"), "{err}");
        let err = parse_ssh_config_args(&args(&["h.example.org", "--user", "a b"])).unwrap_err();
        assert!(err.contains("invalid --user"), "{err}");
        let err = parse_ssh_config_args(&args(&["--user", "alice"])).unwrap_err();
        assert!(err.contains("missing <hostname>"), "{err}");
    }

    // ---- build_client_config ----

    #[test]
    fn client_config_ca_errors_name_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.pem");
        let err = build_client_config(Some(&missing)).unwrap_err();
        assert!(err.contains("absent.pem"), "{err}");
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "").unwrap();
        let err = build_client_config(Some(&empty)).unwrap_err();
        assert!(err.contains("empty.pem") && err.contains("no certificate"), "{err}");
        let garbage = dir.path().join("garbage.pem");
        let bogus = "-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n";
        std::fs::write(&garbage, bogus).unwrap();
        let err = build_client_config(Some(&garbage)).unwrap_err();
        assert!(err.contains("garbage.pem"), "names the file: {err}");
    }

    #[test]
    fn client_config_loads_several_cas_from_one_pem() {
        let dir = tempfile::tempdir().unwrap();
        let a = test_pki::issue("a.test.invalid");
        let b = test_pki::issue("b.test.invalid");
        let bundle = dir.path().join("bundle.pem");
        std::fs::write(&bundle, format!("{}{}", a.ca_pem, b.ca_pem)).unwrap();
        // No panic and no error is the contract; the round trip below proves trust works.
        build_client_config(Some(&bundle)).expect("two CAs in one file");
        build_client_config(None).expect("public roots only");
    }

    // ---- pipe_over_tls round trip ----

    /// A TLS echo server on loopback serving `pki`'s leaf for `host`; returns its address. Echoes
    /// until the client's EOF, then shuts its own write half down (a clean close_notify).
    async fn spawn_tls_echo(pki: &test_pki::TestPki) -> SocketAddr {
        use rustls::pki_types::pem::PemObject;
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(pki.leaf_pem.as_bytes()).map(|c| c.unwrap()).collect();
        let key = PrivateKeyDer::from_pem_slice(pki.key_pem.as_bytes()).unwrap();
        let scfg = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(chain, key).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    // A refused handshake (unknown CA test) just ends this connection.
                    if let Ok(tls) = acceptor.accept(s).await {
                        let (mut rd, mut wr) = tokio::io::split(tls);
                        let _ = tokio::io::copy(&mut rd, &mut wr).await;
                        let _ = wr.shutdown().await;
                    }
                });
            }
        });
        addr
    }

    fn trust_only(ca: &CertificateDer<'static>) -> Arc<rustls::ClientConfig> {
        crate::transport::install_crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.clone()).unwrap();
        Arc::new(rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
    }

    #[tokio::test]
    async fn pipe_over_tls_echoes_and_ends_cleanly_on_client_eof() {
        let pki = test_pki::issue("ssh.test.invalid");
        let addr = spawn_tls_echo(&pki).await;
        let tcp = TcpStream::connect(addr).await.unwrap();

        // stdin/stdout stand-ins: the test writes into `to_pump`, reads from `from_pump`.
        let (mut to_pump, pump_in) = tokio::io::duplex(4096);
        let (pump_out, mut from_pump) = tokio::io::duplex(4096);
        let pump = tokio::spawn(async move {
            pipe_over_tls(pump_in, pump_out, tcp, "ssh.test.invalid", trust_only(&pki.ca_der)).await
        });

        to_pump.write_all(b"SSH-2.0-test\r\n").await.unwrap();
        let mut echoed = [0u8; 64];
        let n = from_pump.read(&mut echoed).await.unwrap();
        assert_eq!(&echoed[..n], b"SSH-2.0-test\r\n", "bytes round-trip through TLS and back");

        // ssh closes our stdin: the pump must shut TLS down and return Ok, and our stdout must
        // reach EOF (not hang) afterwards.
        drop(to_pump);
        let result = tokio::time::timeout(Duration::from_secs(5), pump).await.expect("pump ends").unwrap();
        assert_eq!(result, Ok(()));
        let mut rest = Vec::new();
        from_pump.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty(), "nothing after the echo: {rest:?}");
    }

    #[tokio::test]
    async fn pipe_over_tls_refuses_a_server_signed_by_an_unknown_ca() {
        let served = test_pki::issue("ssh.test.invalid");
        let other = test_pki::issue("ssh.test.invalid");
        let addr = spawn_tls_echo(&served).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (_to_pump, pump_in) = tokio::io::duplex(64);
        let (pump_out, _from_pump) = tokio::io::duplex(64);
        let err = pipe_over_tls(pump_in, pump_out, tcp, "ssh.test.invalid", trust_only(&other.ca_der))
            .await
            .unwrap_err();
        assert!(err.contains("TLS handshake with ssh.test.invalid failed"), "{err}");
        assert!(err.to_ascii_lowercase().contains("certificate"), "names the certificate problem: {err}");
    }

    /// A TLS server that speaks first and hangs up: one banner line, then a clean shutdown --
    /// the shape of an sshd that refuses the connection after its identification string.
    async fn spawn_tls_banner_then_close(pki: &test_pki::TestPki) -> SocketAddr {
        use rustls::pki_types::pem::PemObject;
        let chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(pki.leaf_pem.as_bytes()).map(|c| c.unwrap()).collect();
        let key = PrivateKeyDer::from_pem_slice(pki.key_pem.as_bytes()).unwrap();
        let scfg = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(chain, key).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(scfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(s).await.unwrap();
            tls.write_all(b"SSH-2.0-bye\r\n").await.unwrap();
            let _ = tls.shutdown().await;
        });
        addr
    }

    #[tokio::test]
    async fn pipe_over_tls_returns_when_the_server_closes_first() {
        // The server ending the session (sshd exit) must end the pump so ssh sees EOF on its
        // side -- even though our stdin (`to_pump`) is still wide open.
        let pki = test_pki::issue("ssh.test.invalid");
        let addr = spawn_tls_banner_then_close(&pki).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (to_pump, pump_in) = tokio::io::duplex(64);
        let (pump_out, mut from_pump) = tokio::io::duplex(64);
        let pump = tokio::spawn(async move {
            pipe_over_tls(pump_in, pump_out, tcp, "ssh.test.invalid", trust_only(&pki.ca_der)).await
        });
        let mut banner = Vec::new();
        from_pump.read_to_end(&mut banner).await.unwrap();
        assert_eq!(banner, b"SSH-2.0-bye\r\n", "the server's bytes reach stdout before EOF");
        let result = tokio::time::timeout(Duration::from_secs(5), pump).await.expect("pump ends").unwrap();
        assert_eq!(result, Ok(()));
        drop(to_pump);
    }

    #[test]
    fn test_pki_leaf_key_parses_as_pkcs8() {
        // The terminator loads `privkey.pem` via PrivateKeyDer::from_pem_file; pin the shape
        // rcgen emits so a future rcgen bump cannot silently break the serve.rs tests.
        use rustls::pki_types::pem::PemObject;
        let pki = test_pki::issue("ssh.test.invalid");
        let key = PrivateKeyDer::from_pem_slice(pki.key_pem.as_bytes()).unwrap();
        assert!(matches!(key, PrivateKeyDer::Pkcs8(_)));
    }
}
