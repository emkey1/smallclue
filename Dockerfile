FROM debian:bookworm-slim AS builder

WORKDIR /app

# Install build dependencies
RUN set -eux; \
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
    rm -rf /var/lib/apt/lists/*

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
