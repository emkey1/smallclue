#!/bin/bash
set -euo pipefail

if [[ "$(uname -s)" == "Darwin" ]] && [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    echo "ERROR: On macOS Docker Desktop, run this script without sudo."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker daemon is not reachable. Start Docker Desktop and retry."
    exit 1
fi

BUILD_PROGRESS="${SMALLCLUE_DOCKER_PROGRESS:-plain}"
ALLOW_APT="${SMALLCLUE_DOCKER_ALLOW_APT:-0}"
USE_NO_CACHE="${SMALLCLUE_DOCKER_NO_CACHE:-0}"
IMAGE_TAG="${SMALLCLUE_DOCKER_TAG:-smallclue}"
LOG_DIR="${SMALLCLUE_DOCKER_LOG_DIR:-.}"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/docker-build-$(date +%Y%m%d-%H%M%S).log"

echo "Building SmallClue Docker image..."
echo "  tag: $IMAGE_TAG"
echo "  progress: $BUILD_PROGRESS"
echo "  allow apt fallback: $ALLOW_APT"
echo "  no-cache: $USE_NO_CACHE"
echo "  log: $LOG_FILE"

BUILD_CMD=(
  docker build
  --pull
  --progress="$BUILD_PROGRESS"
  --build-arg "SMALLCLUE_DOCKER_ALLOW_APT=$ALLOW_APT"
  -t "$IMAGE_TAG"
)

if [[ "$USE_NO_CACHE" == "1" ]]; then
  BUILD_CMD+=(--no-cache)
fi

BUILD_CMD+=(.)

if ! "${BUILD_CMD[@]}" 2>&1 | tee "$LOG_FILE"; then
  echo
  echo "Docker build failed. Last 120 log lines:"
  tail -n 120 "$LOG_FILE" || true
  echo
  echo "Error summary:"
  grep -E "(^ERROR:|error:|not complete successfully|did not complete successfully|\\*\\*\\*)" "$LOG_FILE" | tail -n 20 || true
  exit 1
fi

echo "Build complete."
echo "To run the container interactively:"
echo "  docker run --rm -it $IMAGE_TAG"
