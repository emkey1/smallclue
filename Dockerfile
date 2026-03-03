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

# Patch setup_posix_env.sh to skip device management inside Docker
# 1. Disable device population
RUN sed -i '/echo "Populating \/dev..."/{n;s/if \[ "$(uname -s)" = "Linux" \]; then/if false; then/;}' setup_posix_env.sh && \
    sed -i 's/if \[ "$(uname -s)" = "Linux" \] && \[ -d "$ROOTFS" \]; then/if false; then/' setup_posix_env.sh

# Run the setup script to build everything
RUN ./setup_posix_env.sh

# Final stage
FROM scratch

COPY --from=builder /app/rootfs /

# Set shell entrypoint
ENTRYPOINT ["/sbin/init"]
