#!/bin/bash
set -e

if [[ "$(uname -s)" == "Darwin" ]] && [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    echo "ERROR: On macOS Docker Desktop, run this script without sudo."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker daemon is not reachable. Start Docker Desktop and retry."
    exit 1
fi

echo "Building SmallClue Docker image..."
docker build --pull -t smallclue .

echo "Build complete."
echo "To run the container interactively:"
echo "  docker run --rm -it smallclue"
