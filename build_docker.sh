#!/bin/bash
set -e

echo "Building SmallClue Docker image..."
docker build -t smallclue .

echo "Build complete."
echo "To run the container interactively:"
echo "  docker run --rm -it smallclue"
