# ct-agent installation: measurement of today's path

A count of the commands, decisions, variables and undocumented steps an operator
faces when installing `ct-agent`, per use case and platform. Line references are
against `main` at the time of writing (commit `b07f979`); they drift, so re-check
before relying on one.

## Table

| Case | Platform | Basis | Commands | Decisions | Variables (names only) | GUI required | Undocumented | References |
|---|---|---|---|---|---|---|---|---|
| channel | Linux | derived | 7 | 4 | `CT_OIDC_ISSUER`, `CT_OIDC_TOKEN`, `CT_CHANNEL_ROLE`, `CT_CHANNEL_GRANT`, `CT_CHANNEL_HOLDER_KEY`, `CT_CHANNEL_NOISE_KEY`, `CT_CHANNEL_BROKER`, `CT_CHANNEL_RELAY` | `ct-agent login` is an OIDC device grant: the browser step can run on any device, not necessarily the install machine | yes: neither `scripts/setup.sh` nor `scripts/setup.ps1` mentions any `CT_CHANNEL_*` variable (`grep -c CT_CHANNEL` gives 0 for both); register, allowlist and login are described only in `docs/channel.md` | `docs/channel.md:33-62` (login), `:63-75` (register), `:270-298` (variables); `scripts/setup.sh:87-97` (OS detection) |
| channel | macOS | derived | 7 | 4 | as Linux | as Linux | as Linux | as Linux; `scripts/setup.sh:92` (`linux\|darwin`) |
| channel | Windows | derived | at least 7, plus the full tunnel path (below) | at least 4, plus the tunnel decisions | as Linux, plus the tunnel variables | as Linux | yes: `setup.ps1` has no client-only switch, so the full tunnel onboarding runs first | `grep -c ClientOnly scripts/setup.ps1` gives 0; `scripts/setup.ps1:20-26` (parameters); `README.md:50-56` |
| tunnel | Linux | derived | 4 | 4 | `CT_BOOTSTRAP` (or `CT_AGENT_JOIN_TOKEN` + `CT_AGENT_TOKEN`), `CT_AGENT_CP_URL`, `CT_AGENT_HOSTNAME`, `CT_AGENT_ORIGIN`, `CT_AGENT_ORIGIN_PROTO`, `CT_AGENT_MODE`, `CT_AGENT_EDGE_CERT_URL`, `CT_AGENT_CAPABILITY_OUT`, `CT_AGENT_EDGE`, `CT_AGENT_ID` | none for the setup itself | yes: five variables are set silently by the installer and appear in neither the `.env` template nor the README (see below); the `--yes` requirement for a piped direct install is not in the README quickstart | `scripts/setup.sh:149-175` (template), `:177-229` (`ensure_env`), `:231-275` (silent defaults), `:363-384` (`install_direct`); `README.md:30-48` |
| tunnel | macOS | derived | 4 | 4 | as Linux | none for the setup itself | as Linux | as Linux; `scripts/setup.sh:92` |
| tunnel | Windows | derived | 4 | 4 | as Linux (same `CT_AGENT_*` names) | none for the setup itself | as Linux; in addition `Confirm-Mode` does not check whether the session is interactive (no counterpart to `setup.sh:137`) | `scripts/setup.ps1:61-80` (`Confirm-Mode`), `:108-207` (`Import-DotEnv`, defaults); `scripts/setup.sh:137-139` |
| ssh | Linux | derived | 7 (the 4 tunnel commands for the origin host, plus client install, `ssh-config`, `ssh`) | 6 (the 4 tunnel decisions, plus TLS terminate vs. passthrough, plus the certificate source) | tunnel variables, plus `CT_AGENT_ORIGIN_TLS`, `CT_AGENT_TLS_CERT`, `CT_AGENT_TLS_KEY` | none | yes: the three TLS variables are documented only in the help text of `native/src/main.rs`, not in `docs/channel.md`, the README or the `.env` template | `native/src/main.rs:246-259` (SSH help block); `native/src/config.rs:31-36` (constants); `scripts/setup.sh:382` |
| ssh | macOS | derived | 7 | 6 | as Linux | none | as Linux | as Linux |
| ssh | Windows | derived | at least 7: origin and client host each need the full tunnel path | at least 6 | as Linux, on both hosts | none | yes: no client-only switch; the README's CLI-only section shows only the bash command | `grep -c ClientOnly scripts/setup.ps1` gives 0; `README.md:50-56` |
| browser | Linux | derived | 4 (identical to tunnel: the installer already defaults `CT_AGENT_MODE` to browser mode) | 4 | identical to tunnel | setup: none found; use: a browser on the far side | as tunnel | `scripts/setup.sh:235`; `native/src/config.rs:553-557` |
| browser | macOS | derived | 4 | 4 | as tunnel / macOS | as Linux | as tunnel / macOS | as above |
| browser | Windows | derived | 4 | 4 | as tunnel / Windows | as Linux | as tunnel / Windows | `scripts/setup.ps1:166` (same default as `setup.sh:235`) |

### Delimitation of "browser"

Setup (`setup.sh`/`setup.ps1`, `--client-only`) requires a GUI nowhere: the scripts
never open a browser. Using the finished tunnel means requesting the forwarded site
from a browser on the other side, which follows from the product purpose in the
README but is **not stated verbatim anywhere in the repo**. The only browser step the
repo actually demands is the device grant of `ct-agent login` (`docs/channel.md:33-55`),
which belongs to the channel case, not to "browser".

### Windows and administrator rights

`scripts/setup.ps1` installs no Windows service (`grep -niE 'new-service|sc\.exe|nssm|elevat|uac|administrator'` gives no match). The agent is started as an ordinary hidden child process (`scripts/setup.ps1:262`, `Start-Process … -WindowStyle Hidden`) with the rights of the invoking session.

## Method

- **derived**: read from documentation or source, with file:line; not executed.
- **not measured**: neither executed nor derivable from a citable source.
- **Command**: a line the operator types in the shell session (a `curl … | bash`, an editor pass, a single CLI call). Opening the session itself is not counted.
- **Decision**: any point where script, documentation or source leaves the operator a choice between at least two options that changes the rest of the path (a flag, a multi-valued variable, a y/N prompt). Defaults the installer sets silently are not decisions as long as the operator need not override them.

Only the bash `ensure_env` unit test (`scripts/tests/test-setup-sh-ensure-env.sh`) and
grep checks were executed. The remaining setup tests need network access and were not
run, so every count in the table is **derived**, none is a timed end-to-end
measurement. macOS and Windows were not executed at all.

## Provenance per row

**channel / Linux, macOS (7 commands):** (1) `curl … | bash -s -- --client-only` (`README.md:55`); (2) `ct-agent login` with `CT_OIDC_ISSUER` set (`docs/channel.md:40-43`); (3) the browser step of the device grant on any device (`docs/channel.md:44-49`, part of the path but not typed in the session); (4) setting the `CT_CHANNEL_*` variables (`docs/channel.md:270-298`); (5) `ct-agent channel register` (`docs/channel.md:63-75`); (6) `ct-agent channel allowlist …` (`docs/channel.md:35,49`); (7) `ct-agent channel` to join. Four decisions: broker/relay versus direct address (`docs/channel.md:19-24`); `register` versus `register --rekey` (`:70-74`); the transport ladder and front-door settings (`:79-86`); `CT_CHANNEL_REQUIRE_PEER_GRANT` on or off (`:289`).

**channel / Windows:** as above, but there is no client-only switch, so the full tunnel path runs first to obtain `ct-agent.exe`.

**tunnel (all platforms), 4 commands:** (1) first run of the installer without `.env` writes `.env.example` and exits 1 (Linux, covered by `test-setup-sh-ensure-env.sh`); (2) copy `.env.example` to `.env`; (3) fill in `.env`; (4) second run with `--yes`/`-Yes`. Four decisions: (a) `CT_BOOTSTRAP` versus `CT_AGENT_JOIN_TOKEN` + `CT_AGENT_TOKEN` (`scripts/setup.sh:182-199`); (b) `--docker` versus direct install (`:31-85`); (c) `--yes`, which a piped installer needs because stdin is not a terminal; enforced on Linux/macOS by `[ ! -t 0 ]` (`:137-139`), not enforced in `Confirm-Mode` on Windows (`scripts/setup.ps1:61-80`); (d) `--template` or not (`:31-49`).

**ssh:** the tunnel row of the platform for the origin host, plus three commands (client install, `ct-agent ssh-config <hostname> >> ~/.ssh/config`, `ssh <hostname>`; `native/src/main.rs:258-259`) and two decisions (`CT_AGENT_ORIGIN_TLS` terminate vs. passthrough, `native/src/main.rs:246-257`; certificate source, `:249-252`).

**browser:** identical to tunnel, because `ensure_env`/`Import-DotEnv` already default `CT_AGENT_MODE` to browser mode (`scripts/setup.sh:235`, `scripts/setup.ps1:166`). The difference is in use only.

## Five variables the installer sets silently

| Variable | Read at | Without it | Set by the installer | In `.env` template / README |
|---|---|---|---|---|
| `CT_AGENT_EDGE_CERT_URL` | `native/src/main.rs:1267` | the agent waits for the shared-volume file `/shared/edge-cert.der` (`:1259`); the comment at `scripts/setup.sh:233-234` says it hangs forever rather than erroring | `scripts/setup.sh:236`, `scripts/setup.ps1:167` (default: `CT_AGENT_CP_URL`) | no |
| `CT_AGENT_CAPABILITY_OUT` | `native/src/main.rs:1261` | defaults to `/shared/capability.bin`, a compose shared-volume path, which fails with ENOENT on an ordinary machine (comment at `scripts/setup.sh:255-258`) | `scripts/setup.sh:259`, `scripts/setup.ps1:191` (default: `<state dir>/capability.bin`) | no |
| `CT_AGENT_EDGE` | `native/src/config.rs:534` (default `127.0.0.1:4433`) | no hang, but a silent pointer at localhost | `scripts/setup.sh:260-269`, `scripts/setup.ps1:192-200` (auto-detected from `<CP_URL>/network-info`, otherwise the script aborts) | no |
| `CT_AGENT_MODE` | `native/src/config.rs:555-556` (case-insensitive comparison with `browser`) | falls back to passthrough, with no error | `scripts/setup.sh:235`, `scripts/setup.ps1:166` (default `browser`) | no (mentioned in the SSH help block, `native/src/main.rs:246`) |
| `CT_AGENT_ID` | `scripts/setup.sh:244-254` | a fresh id per run would break restore of the persisted identity | `scripts/setup.sh:251-254`, `scripts/setup.ps1:174-186` (reused from the state file, else generated) | no |

`CT_AGENT_HOSTNAME` is required by the installer (`scripts/setup.sh:220`, `scripts/setup.ps1:152`) and is present in the template (`scripts/setup.sh:166`), but without a format hint. Note that `native/src/config.rs:454-470` warns when a hostname is set but the mode is not browser.

## Five largest hurdles

1. **The silently set variables are not in the `.env` template or the README.** Affects the six tunnel and browser rows. `scripts/setup.sh:231-275` against `:149-175`; `scripts/setup.ps1:162-201`.
2. **No client-only switch in `scripts/setup.ps1`.** On Windows there is no way to install only the CLI; the full tunnel onboarding is forced. Affects channel/Windows and ssh/Windows. `scripts/setup.ps1:20-26`; `README.md:50-56` documents only the bash command.
3. **No service unit is shipped for any platform.** There is no systemd, launchd or Windows service file in the repo (`find . \( -name '*.service' -o -name '*.plist' \)` gives nothing). The installers background the process with `nohup` (`scripts/setup.sh:382`) or `Start-Process` (`scripts/setup.ps1:262`); `ct-agent-supervisor` exists for restarts (`README.md:66-72`) but the installer does not set it up.
4. **`--yes` is needed for a piped direct install but is not in the README quickstart.** On Windows the confirmation prompt does not check for an interactive session. `scripts/setup.sh:137-139` against `scripts/setup.ps1:61-80`; `README.md:30-48`.
5. **`CT_AGENT_ORIGIN_TLS`, `CT_AGENT_TLS_CERT` and `CT_AGENT_TLS_KEY` (ssh case) are documented only in the help text** of `native/src/main.rs:246-257`, not in `docs/channel.md`, the README or the template.
