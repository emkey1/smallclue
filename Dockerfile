FROM golang:bookworm AS microbuilder

ARG TARGETARCH

RUN set -eux; \
    MICRO_VERSION="2.0.15"; \
    mkdir -p /tmp/src /out /tmp/micro; \
    cd /tmp/src; \
    found=0; \
    candidates=""; \
    case "${TARGETARCH:-amd64}" in \
      amd64) \
        candidates="micro-${MICRO_VERSION}-linux64-static.tar.gz micro-${MICRO_VERSION}-linux64.tar.gz"; \
        ;; \
      arm64) \
        candidates="micro-${MICRO_VERSION}-linux-arm64.tar.gz"; \
        ;; \
      arm) \
        candidates="micro-${MICRO_VERSION}-linux-arm.tar.gz"; \
        ;; \
      *) \
        candidates="micro-${MICRO_VERSION}-linux64-static.tar.gz micro-${MICRO_VERSION}-linux64.tar.gz"; \
        ;; \
    esac; \
    for asset in $candidates; do \
      if curl -fL --retry 3 --retry-delay 2 "https://github.com/zyedidia/micro/releases/download/v${MICRO_VERSION}/${asset}" -o micro.tar.gz; then \
        tar -xzf micro.tar.gz -C /tmp/micro; \
        micro_bin="$(find /tmp/micro -type f -name micro | head -n 1)"; \
        if [ -n "$micro_bin" ] && [ -f "$micro_bin" ]; then \
          cp "$micro_bin" /out/micro; \
          chmod 0755 /out/micro; \
          found=1; \
          break; \
        fi; \
        rm -rf /tmp/micro/*; \
      fi; \
    done; \
    if [ "$found" -eq 0 ]; then \
      rm -rf /tmp/src/* /tmp/micro/* /root/.cache/go-build /go/pkg/mod; \
      curl -fL --retry 3 --retry-delay 2 "https://codeload.github.com/zyedidia/micro/tar.gz/refs/tags/v${MICRO_VERSION}" -o micro.tar.gz; \
      tar -xzf micro.tar.gz; \
      cd "micro-${MICRO_VERSION}"; \
      CGO_ENABLED=0 GOMAXPROCS=1 GOFLAGS="-p=1" GOCACHE=/tmp/gocache GOMODCACHE=/tmp/gomodcache \
        go build -trimpath -ldflags="-s -w" -o /out/micro ./cmd/micro; \
      rm -rf /tmp/gocache /tmp/gomodcache; \
    fi; \
    rm -rf /tmp/src /tmp/micro

FROM buildpack-deps:bookworm AS builder

WORKDIR /app

ARG SMALLCLUE_DOCKER_ALLOW_APT=0

# Ensure build dependencies are present (buildpack-deps usually already has these)
RUN set -eux; \
    need_apt=0; \
    for cmd in gcc g++ make git curl; do \
        command -v "$cmd" >/dev/null 2>&1 || need_apt=1; \
    done; \
    printf '#include <openssl/ssl.h>\n' | gcc -E - >/dev/null 2>&1 || need_apt=1; \
    printf '#include <zlib.h>\n' | gcc -E - >/dev/null 2>&1 || need_apt=1; \
    if [ "$need_apt" -eq 1 ] && [ "${SMALLCLUE_DOCKER_ALLOW_APT:-0}" = "1" ]; then \
        if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
            sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources; \
        elif [ -f /etc/apt/sources.list ]; then \
            sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list; \
        fi; \
        rm -rf /var/lib/apt/lists/*; \
        apt-get clean; \
        apt-get update \
            -o Acquire::Retries=5 \
            -o Acquire::http::No-Cache=true \
            -o Acquire::https::No-Cache=true; \
        apt-get install -y --no-install-recommends \
            build-essential \
            git \
            autoconf \
            automake \
            libtool \
            libssl-dev \
            zlib1g-dev \
            ca-certificates \
            curl; \
        rm -rf /var/lib/apt/lists/*; \
    elif [ "$need_apt" -eq 1 ]; then \
        echo "Required build dependencies were not detected in the base image." >&2; \
        echo "Rebuild with --build-arg SMALLCLUE_DOCKER_ALLOW_APT=1 to enable apt fallback." >&2; \
        exit 1; \
    fi

# Copy source
COPY . .
COPY --from=microbuilder /out/micro /app/third-party/micro-bin/micro

# Patch setup_posix_env.sh to skip device management inside Docker
# 1. Disable device population
RUN sed -i '/echo "Populating \/dev..."/{n;s/if \[ "$(uname -s)" = "Linux" \]; then/if false; then/;}' setup_posix_env.sh && \
    sed -i 's/if \[ "$(uname -s)" = "Linux" \] && \[ -d "$ROOTFS" \]; then/if false; then/' setup_posix_env.sh

# Run the setup script to build everything
RUN ./setup_posix_env.sh

# Keep only the generated rootfs in the final image payload.
RUN set -eux; \
    find /app -mindepth 1 -maxdepth 1 ! -name rootfs -exec rm -rf {} +; \
    rm -rf /root/.cache /tmp/*

# Final image: avoid an additional full rootfs copy layer, which can fail
# with ENOSPC on Docker Desktop when builder cache is near capacity.
FROM builder

# Set shell entrypoint (run inside the generated rootfs)
ENTRYPOINT ["/usr/sbin/chroot", "/app/rootfs", "/sbin/init"]
