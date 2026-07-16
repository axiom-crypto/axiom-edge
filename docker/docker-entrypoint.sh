#!/bin/sh
set -e

# This script allows running the edge-manager, edge-worker, or other binaries.
# The selection is based on the first argument passed to the script.

# Disable core dumps to prevent hanging on core dumps
ulimit -c 0

if [ "$1" = "edge-manager" ]; then
  shift
  exec /usr/bin/tini -- /app/edge-manager "$@"
elif [ "$1" = "edge-worker" ]; then
  shift
  exec /usr/bin/tini -- /app/edge-worker "$@"
else
  # If the command is not one of the above, execute it directly.
  # This allows running other commands like "sh" for debugging.
  exec /usr/bin/tini -- "$@"
fi
