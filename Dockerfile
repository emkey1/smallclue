FROM buildpack-deps:bookworm AS builder

WORKDIR /app

# Ensure build dependencies are present (buildpack-deps usually already has these)
RUN set -eux; \
    need_apt=0; \
    for cmd in gcc g++ make git autoconf automake libtool curl ssh; do \
        command -v "$cmd" >/dev/null 2>&1 || need_apt=1; \
    done; \
    [ -f /usr/include/openssl/ssl.h ] || need_apt=1; \
    [ -f /usr/include/zlib.h ] || need_apt=1; \
    if [ "$need_apt" -eq 1 ]; then \
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
            curl \
            openssh-client; \
        rm -rf /var/lib/apt/lists/*; \
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
