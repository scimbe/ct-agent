# Minimal ct-agent runtime image -- downloads the prebuilt release binary matching
# the build platform, no Rust toolchain and no source checkout involved. This is
# deliberately NOT the build-from-source pattern CADS-Tunnel's examples/help-site/
# Agent.Dockerfile uses (that one exists to test against unreleased commits); this
# one is what an end customer's `scripts/setup.sh --docker` actually runs.
#
#   docker build -t ct-agent:local https://github.com/scimbe/ct-agent.git#main:docker

FROM ubuntu:24.04
# Must match the glibc the release binaries are actually linked against: the
# release workflow (.github/workflows/release.yml) builds every Linux target on
# ubuntu-latest (GLIBC 2.39) -- debian:bookworm-slim's older GLIBC 2.36 makes the
# downloaded binary fail to even start ("GLIBC_2.39 not found"), confirmed by
# actually running the built image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Security-hardening pass: run as an unprivileged uid/gid rather than root, so a
# future code-execution bug in the Agent's QUIC/Noise/HTTP parsing hands an
# attacker an unprivileged account instead of container-root. 65532 matches this
# product family's existing non-root baseline (CADS-Tunnel's relay-node, #305/#667)
# -- one convention across the fleet, not a value picked in isolation here. No
# /etc/passwd entry is created (the Agent only ever reads CT_AGENT_* env vars, no
# home-dir lookups) -- entrypoint.sh drops privileges via `chroot --userspec`
# instead of `su`/`gosu`, both of which would need either a passwd entry or an
# extra downloaded binary.
RUN groupadd --gid 65532 ctagent

# Detect the platform via `uname` at RUN time rather than relying on the
# `TARGETARCH`/`TARGETOS` build ARGs (#3): those are only auto-populated by
# BuildKit's multi-platform machinery, which `scripts/setup.sh`'s plain
# `docker build` invocation (no `buildx`, no `--platform`) doesn't engage on
# every Docker install -- classic builder, `DOCKER_BUILDKIT=0`, and some buildx
# driver configs all leave them empty, producing "unsupported TARGETARCH: "
# with nothing after the colon. `uname` runs unconditionally inside the RUN
# step's own execution environment, so it reports correctly whether that's the
# host's native architecture (plain single-platform build) or an emulated
# target platform (genuine `buildx --platform=...` cross-build under QEMU) --
# no dependency on which builder or flags produced the image.
RUN arch="$(uname -m)" \
    && case "${arch}" in \
      x86_64|aarch64)  rel_arch="${arch}" ;; \
      i386|i686)       rel_arch=i686 ;; \
      *) echo "unsupported architecture: ${arch}" >&2; exit 1 ;; \
    esac \
    && os="$(uname -s | tr '[:upper:]' '[:lower:]')" \
    && case "${os}" in \
      linux) rel_os=linux ;; \
      *) echo "unsupported OS: ${os} (this image targets Linux containers)" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://github.com/scimbe/ct-agent/releases/latest/download/ct-agent-${rel_os}-${rel_arch}" \
       -o /usr/local/bin/ct-agent \
    && chmod +x /usr/local/bin/ct-agent

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# The container still STARTS as root (entrypoint.sh's own job is to migrate any
# existing root-owned mounted state, then drop to 65532:65532 before exec'ing the
# real binary) -- so no USER directive here. Do not add one; it would skip the
# migration step entirely and turn every already-deployed volume into a
# Permission-denied failure on the next container recreate.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["ct-agent"]
