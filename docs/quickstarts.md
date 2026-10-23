<!-- Commands in this page are taken from `ct-agent --help`, `docs/channel.md` and `scripts/setup.sh`
     of the same release (v0.7.39). -->
# Quickstarts

Four short paths from a fresh machine to a visible result. For what separates them, read the
comparison table in the [README](../README.md#tunnel-or-channel) first.

| | You want | Section |
|---|---|---|
| 1 | a website or TCP service on your machine reachable under a public hostname | [Tunnel](#1-tunnel) |
| 2 | two members to exchange bytes end-to-end encrypted, without either opening a port | [Channel](#2-channel) |
| 3 | `ssh <hostname>` to a machine behind NAT, through a tunnel | [SSH over a tunnel](#3-ssh-over-a-tunnel) |
| 4 | `ssh` to a machine behind NAT, through a channel | [SSH over a channel](#4-ssh-over-a-channel) |

Placeholders are written in angle brackets (`<name>.example.org`, `<edge-host>`). `<control-plane>` is
the base URL of your CADS-Tunnel control plane, the value you give `ct-agent` as `CT_AGENT_CP_URL`
(`https://bunsenbrenner.org` for the hosted deployment). In these steps secrets come from the environment
or a `0600` file instead of a typed argument; `scripts/quickstart.sh` also keeps them off the command
lines it builds. That promise covers only the script itself. The agent writes the ssh owner key to
`ct-agent.log` on its first terminate-mode start, so treat that log as secret.

A note on QUIC: `ct-agent` speaks QUIC (UDP) where it can and falls back to TLS over TCP `:443`
by itself. You do not choose it per path. A tunnel registers over QUIC first (the
`CT_AGENT_REGISTER_TCP_ONLY=1` switch pins it to TCP), a channel tries direct QUIC to the edge's broker and
relay first and then the `:443` front door ([transport ladders](channel.md#transport-selection-the-dial-ladders)).
`ct-agent ssh` always uses TLS over TCP `:443`.

---

## 1. Tunnel

**Status:** steps 2–3 run with v0.7.39; the portal steps not run.

**Short path:** `scripts/quickstart.sh tunnel` asks for the hostname and the token of the Install page (hidden), writes the `.env`, runs `setup.sh` and checks the public URL. The steps below are the manual reference.

**Script status:** tested with stubs (no network); not yet run against a real service.

**Result:** a service listening on `127.0.0.1:8080` of your machine answers under your tunnel's
public hostname, although your machine only ever dials out.

1. Create the tunnel in the portal of your control plane (`<control-plane>/portal/tunnels`) and open
   its **Install** page. It shows a
   short-lived bootstrap token and the hostname of the tunnel.
2. Start something to publish, here a throw-away web server on loopback:

   ```bash
   python3 -m http.server 8080 --bind 127.0.0.1
   ```

3. In a second terminal, in an empty directory, run the guided setup. On the first run it
   writes `.env.example` and stops. Without a terminal (a pipe, CI) the script cannot ask its
   direct-host confirmation and aborts; pass `--yes` there (`bash setup.sh --yes`):

   ```bash
   curl -fsSL https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.sh -o setup.sh
   bash setup.sh
   ```

4. Copy the template and fill in the values from the Install page, then run the script again:

   ```bash
   cp .env.example .env
   # edit .env:
   #   CT_BOOTSTRAP=<token from the Install page>
   #   CT_AGENT_CP_URL=https://bunsenbrenner.org
   #   CT_AGENT_HOSTNAME=<name>.example.org     # as shown on the Install page
   #   CT_AGENT_ORIGIN=127.0.0.1:8080
   #   CT_AGENT_ORIGIN_PROTO=tcp
   bash setup.sh
   ```

   Add `--docker` to run the agent as a container instead of directly on the host. The
   direct-host path asks for confirmation (`--yes` skips it, and is required without a terminal)
   because it should run on an isolated VM, container or dedicated host.

5. **You are done when** the script ends with `done — current tier: …` and `ct-agent.log`
   shows the agent registered; then open `https://<name>.example.org/` in a browser or:

   ```bash
   curl -I https://<name>.example.org/
   ```

   The tier (Rot, Gelb, Grün) tells whose certificate the browser sees. At Gelb the origin must serve
   plain HTTP. To move to Grün (your own certificate), the script prints the exact
   `ct-agent certificate` command to run.

Check later with `ct-agent status` (needs `CT_AGENT_METRICS_LISTEN`, otherwise it prints the last
recorded events), stop with `kill $(cat ct-agent.pid)`.

---

## 2. Channel

**Status:** run end to end with v0.7.39 against a self-hosted edge and control plane (front door :443, relay).

**Short path:** `scripts/quickstart.sh channel` runs the whole path on one machine (you are the operator and both members), sends a test line and reports success or the first failed stage. For several machines use `--role operator` and `--role member`; they exchange a few pasted text blocks (public values and the grant only; three rounds). The steps below are the manual reference.

**Script status:** tested with stubs (no network); not yet run against a real service.

**Result:** bytes typed on member B appear on member A, end-to-end encrypted (Noise_IK). The
edge brokers and relays the connection and sees only ciphertext.

Roles: an **operator** owns the channel and signs grants; **member A** accepts, **member B**
initiates. One person can be all three.

1. On every machine, install the CLI only (no `.env`, no running agent needed):

   ```bash
   curl -fsSL https://raw.githubusercontent.com/scimbe/ct-agent/main/scripts/setup.sh | bash -s -- --client-only
   sudo install -m 0755 ./ct-agent /usr/local/bin/ct-agent
   ```

2. Operator: log in once (prints a code and a URL to open in any browser), then create the operator key:

   ```bash
   CT_OIDC_ISSUER=https://auth.bunsenbrenner.org/realms/ct-demo ct-agent login
   eval "$(ct-agent channel operator-init)"      # sets CT_CHANNEL_OPERATOR_KEY; the comment line shows operator_pubkey
   ```

   Keep the private operator key (`CT_CHANNEL_OPERATOR_KEY`) beyond this shell session, in a `0600`
   file. `ct-agent channel grant` signs with it, so without it you cannot issue further grants for the
   channel. Registering again with a different key needs `--rekey` and stops every grant signed by the
   old key from verifying.

3. Each member creates a local identity and sends the two **public** values
   (`CT_CHANNEL_HOLDER_PUBKEY`, `CT_CHANNEL_NOISE_PUBKEY`) to the operator. The private keys stay
   on the member's machine.

   ```bash
   ct-agent channel init > member.env && chmod 600 member.env
   grep PUBKEY member.env
   ```

4. Each member computes its own material from the operator's public key and the *other* member's
   holder public key, and sends `channel_id` and `noise_attestation` to the operator (both members
   get the same `channel_id`):

   ```bash
   . ./member.env
   CT_CHANNEL_OPERATOR_PUBKEY=<operator_pubkey> CT_CHANNEL_BRIDGE_HOLDER=<the other member's holder pubkey> \
     ct-agent channel member-material
   ```

5. Operator: register the channel with the control plane, add both members, then sign one grant per
   member (`CT_GRANT_DIRECTION` is `accept` for A and `initiate` for B; `CT_GRANT_EXPIRES` is Unix seconds).

   ```bash
   CT_AGENT_CP_URL=<control-plane> CT_CHANNEL_ID=<channel_id> ct-agent channel register
   ```

   Adding a member is an HTTP call to the control plane, `POST /me/channels/<channel_id>/members`, as the
   channel's owner (the same account you logged in with). It takes the member's `holder_pubkey`,
   `noise_pubkey` and `noise_attestation`, and the control plane verifies the attestation. Put a bearer
   token of that account (it is valid only a few minutes: add the members right after `ct-agent login`,
   and log in again on a `401`) into a file (`umask 077; ...  > token`, for example with
   `scripts/channel-ops/mint-oidc-token.sh` from the CADS-Tunnel repository) and let curl read the header
   from stdin so the token never appears in the process list. Repeat for both members; a `409` means the
   member is already added:

   ```bash
   CP=<control-plane>; CH=<channel_id>
   curl -sS -X POST "$CP/me/channels/$CH/members" -H 'content-type: application/json' \
     --config - -d '{"holder":"<holder_pubkey>","noise_pubkey":"<noise_pubkey>","noise_attestation":"<noise_attestation>"}' <<EOF
   header = "Authorization: Bearer $(cat token)"
   EOF
   ```

   (`scripts/channel-ops/provision-link-channel.sh` in the CADS-Tunnel repository does register, member
   add and grant signing for both sides in one run.) Then sign the grants:

   ```bash
   CT_GRANT_CHANNEL=<channel_id> CT_GRANT_MEMBER_HOLDER=<member holder pubkey> \
   CT_GRANT_DIRECTION=initiate CT_GRANT_EXPIRES=$(( $(date +%s) + 86400 )) \
     ct-agent channel grant           # prints the member's CT_CHANNEL_GRANT
   ```

   Without the member add, every join is refused with `edge broker refused the channel join`
   (see the [note on admission](channel.md#modes)).

6. Member A (accept) and member B (initiate) start with the same edge addresses. Both use the
   `:443` front door only, which keeps both halves in the same pairer
   ([why](channel.md#pairing-reality-until-cads-tunnel495-lands)). Get the edge values from the control
   plane: `curl -fsS <control-plane>/network-info` returns `channel_broker_port`, `channel_relay_port`
   and `channel_relay_gate_port` (the `:443` front door); the host is the control plane's host. The
   front-door certificate is the control plane's CA, which `GET <control-plane>/pki/ca` returns as raw DER.
   Convert it to hex once:

   ```bash
   curl -fsS <control-plane>/pki/ca | od -An -v -tx1 | tr -d ' \n'
   ```

   Then start both sides:

   ```bash
   . ./member.env
   export CT_CHANNEL_BROKER=<edge-host>:4435 CT_CHANNEL_RELAY=<edge-host>:4436
   export CT_CHANNEL_FRONT_DOOR=<edge-host>:443 CT_CHANNEL_FRONT_DOOR_CERT=<hex DER of the edge CA>
   export CT_CHANNEL_FRONT_DOOR_ONLY=1 CT_CHANNEL_RELAY_ONLY=1
   export CT_CHANNEL_GRANT=<the member's grant>

   # member A (start this first; an initiating side that comes earlier waits a long time per attempt)
   CT_CHANNEL_ROLE=accept ct-agent channel > received.txt

   # member B
   echo "hello from B" | CT_CHANNEL_ROLE=initiate ct-agent channel
   ```

7. **You are done when** `received.txt` on A contains `hello from B` (after a few seconds). With stdin
   on a terminal, A does not exit by itself after receiving: end A's input with Ctrl-D, and both
   members exit with status 0. Stopping A with Ctrl-C instead makes B report `ok=false` and exit
   non-zero once both members run a ct-agent with delivery confirmation, because A's direction never
   ended ([why](channel.md#delivery-confirmation-protocol-v2-299)). A started without a
   terminal (`nohup`, `</dev/null`, a service unit) has its stdin at end-of-file from the start. That
   works when both members run a ct-agent with [delivery confirmation](channel.md#delivery-confirmation-protocol-v2-299)
   (`delivery=ack` in the `channel_session` events), whatever the edge: A still receives, A exits once
   B has finished, and `ok=true` with exit status 0 means that the peer confirmed the bytes. If a
   member runs an older ct-agent, it works against an edge with CADS-Tunnel v0.5.0 or later
   (CADS-Tunnel#856); against an older edge, keep A's stdin open on the `:443` front door (a
   terminal, or a FIFO with a writer that stays open), because there A silently loses the data
   ([#299](https://github.com/scimbe/ct-agent/issues/299)). In that legacy case `ok=true` only says
   that the transport closed cleanly ([raw pipe](channel.md#modes)). The forward mode in section 4 is
   not affected. Without a service handler `ct-agent channel` is a raw pipe: stdin goes to the peer
   and the peer's bytes arrive on stdout.

Other modes (a held service session with one JSON line per call, a persistent server, a call
without any broker) are in the [channel reference](channel.md#modes).

---

## 3. SSH over a tunnel

**Status:** `ssh-config` and `ssh-owner show` checked offline; not run end to end (needs tier Grün).

**Short path:** `scripts/quickstart.sh ssh-tunnel` on the agent host (it prints what tier Grün needs first), then `scripts/quickstart.sh ssh-tunnel --role client` on the client. `--yes` accepts defaults only: replacing a different `~/.ssh/ct-agent-<host>.owner` needs `--allow-ssh-key-overwrite`, and adding the stanza to `~/.ssh/config` needs `--append-ssh-config` (without it the stanza is printed for you to add). The steps below are the manual reference.

**Script status:** tested with stubs (no network); not yet run against a real service. The tier-Grün path has not been run end to end by anyone.

**Result:** `ssh <name>.example.org` reaches the sshd of a machine that has no open port. The
tunnel's hostname is the SSH host; the client speaks SSH inside TLS to the edge on `:443`.

Prerequisite: a tunnel from [section 1](#1-tunnel) at tier **Grün**, because the agent must
terminate TLS with the hostname's own certificate (an sshd cannot).

**On the machine running sshd (agent host):**

1. Get the certificate pair, using the values from the Install page; `ct-agent certificate` keeps it renewed:

   ```bash
   CT_AGENT_CP_URL=https://bunsenbrenner.org CT_AGENT_TOKEN=<routing token> \
   CT_AGENT_HOSTNAME=<name>.example.org CT_ACME_CERT_OUT_DIR=./ct-agent-cert \
     ct-agent certificate
   ```

2. Stop the agent from section 1 (`kill $(cat ct-agent.pid)`), add these lines to its `.env` and run
   `bash setup.sh` again (direct-host mode; it restores the identity kept in `./.ct-agent-state`):

   ```bash
   CT_AGENT_MODE=browser
   CT_AGENT_ORIGIN=127.0.0.1:22
   CT_AGENT_ORIGIN_TLS=terminate
   CT_ACME_CERT_OUT_DIR=./ct-agent-cert
   ```

   In terminate mode the agent terminates the client's TLS with the certificate pair from that
   directory, forwards the SSH bytes to sshd, and fails at startup if the pair cannot be loaded. It
   also needs a state directory, because it generates an owner key there at its first start. Once the
   agent has started, print the key (before that, `show` answers "no owner key yet"; `ct-agent ssh-owner init`
   creates it right away):

   ```bash
   CT_AGENT_STATE_DIR=./.ct-agent-state ct-agent ssh-owner show
   ```

**On the client:**

3. Install the CLI (step 1 of [section 2](#2-channel)) and write the SSH config. `--owner-key` stores the key
   in `~/.ssh/ct-agent-<name>.example.org.owner` (mode `0600`) and references that file:

   ```bash
   ct-agent ssh-config <name>.example.org --user <your-login> --owner-key <owner key> >> ~/.ssh/config
   ```

4. Connect:

   ```bash
   ssh <name>.example.org
   ```

**You are done when** you get the shell prompt of the agent host. If the connection fails, ssh
shows the diagnostics of the ProxyCommand on stderr, prefixed `ct-agent ssh:`. For a private CA
add `--ca <pem-file>` to `ssh-config`.

Owner authentication is on by default: before the first SSH byte the agent sends a challenge and the
client answers with the owner key, so reaching the hostname is not enough to talk to sshd. sshd's own
login still applies on top.

---

## 4. SSH over a channel

**Status:** run end to end with v0.7.39 against the hosted edge (front door :443, relay): login, scp of 50 MiB in both directions, 5 parallel sessions, restart of the accepting side. Measured: login median 0.78 s, about 1.9 MiB/s over the relay.

**Short path:** `scripts/quickstart.sh ssh-channel` does section 2 plus the forward and prints the finished `ssh` line; `--role operator|member` for several machines. The forward is opt-in even with `--yes`: add `--enable-forward` to turn it on without a question. The forward warning below applies and the script repeats it. The steps below are the manual reference.

**Script status:** tested with stubs (no network); not yet run against a real service.

**Result:** `ssh -p 2222 <user>@127.0.0.1` on the client reaches the sshd of the accepting
machine, which stays bound to its loopback and is never published. There is no `ssh`
subcommand for channels; it is the generic **TCP forward** (`CT_CHANNEL_FORWARD`, off
by default) used with port 22.

> The forward is opt-in, and the reference says not to enable it in production until grant revocation
> ends running forwarded streams ([#45](https://github.com/scimbe/ct-agent/issues/45)); see
> [TCP forward over a paired channel](channel.md#tcp-forward-over-a-paired-channel-255--opt-in-default-off).
> What was measured: on the relay path, removing the member at the control plane ended a running forwarded
> SSH session within about 30 seconds (the edge's sweep) and new joins were refused. For peers that have
> upgraded to a direct connection this was not measured. The warning stands.

1. Set up the channel as in [section 2](#2-channel), steps 1 to 5. The machine with the sshd is
   member A (accept), the client is member B (initiate).
2. Start member A first. Allow exactly one target and start the accept side with `CT_CHANNEL_SERVE=1`:
   without it the accept side takes exactly one session and then exits, so the login does not come back
   after B restarts; with it A stays parked at the broker and serves every paired session (up to
   `CT_CHANNEL_SERVE_CONCURRENCY`, default 8). Without `CT_CHANNEL_FORWARD_ALLOW` every forward request is refused:

   ```bash
   . ./member.env      # plus the CT_CHANNEL_* edge settings and CT_CHANNEL_GRANT from section 2, step 6
   CT_CHANNEL_ROLE=accept CT_CHANNEL_SERVE=1 CT_CHANNEL_FORWARD_ALLOW=127.0.0.1:22 ct-agent channel
   ```

3. On member B, open the local listener (loopback only) that is forwarded to that target:

   ```bash
   . ./member.env      # same settings, B's own grant
   CT_CHANNEL_ROLE=initiate CT_CHANNEL_FORWARD=127.0.0.1:2222=127.0.0.1:22 ct-agent channel
   ```

   It prints `CT_CHANNEL_FORWARD 127.0.0.1:2222 -> 127.0.0.1:22 …`.

4. In a second terminal on B:

   ```bash
   ssh -p 2222 <user>@127.0.0.1
   ```

   The first time, ssh asks you to confirm the host key of member A's machine under `127.0.0.1:2222`
   (not of your own machine). To keep it apart from other things on that port, add
   `-o HostKeyAlias=<name>`.

**You are done when** you get the shell prompt of member A's machine. If the session drops (peer
restart, network), the listener on B reconnects with backoff. Once B's own grant has expired, or the grant
check has recorded the end of the session, it stays bound but closes every new connection and logs the
reason. Do not rely on revoking a grant to stop a running forward (see the note at the top).
