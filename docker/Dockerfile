# Minimal ct-agent runtime image -- downloads the prebuilt release binary matching
# the build platform, no Rust toolchain and no source checkout involved. This is
# deliberately NOT the build-from-source pattern CADS-Tunnel's examples/help-site/
# Agent.Dockerfile uses (that one exists to test against unreleased commits); this
# one is what an end customer's `scripts/setup.sh --docker` actually runs.
#
# Built with buildx so $TARGETOS/$TARGETARCH resolve to the host platform automatically:
#   docker build -t ct-agent:local https://github.com/scimbe/ct-agent.git#main:docker

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

ARG TARGETOS
ARG TARGETARCH
# Docker's TARGETARCH values (amd64/arm64/386) don't match this repo's release
# asset names (x86_64/aarch64/i686, see .github/workflows/release.yml) -- map them.
RUN case "${TARGETARCH}" in \
      amd64) rel_arch=x86_64 ;; \
      arm64) rel_arch=aarch64 ;; \
      386)   rel_arch=i686 ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && case "${TARGETOS}" in \
      linux) rel_os=linux ;; \
      *) echo "unsupported TARGETOS: ${TARGETOS} (this image targets Linux containers)" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://github.com/scimbe/ct-agent/releases/latest/download/ct-agent-${rel_os}-${rel_arch}" \
       -o /usr/local/bin/ct-agent \
    && chmod +x /usr/local/bin/ct-agent

CMD ["ct-agent"]
