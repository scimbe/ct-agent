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

CMD ["ct-agent"]
