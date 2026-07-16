#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# The vm-vk must be built from the SAME VM config as the proofs it verifies.
# If keys were generated with a custom --openvm-config-file, set EDGE_OPENVM_CONFIG
# to that same TOML before running this (start-provers stashes a copy at
# {artifacts_path}/openvm-config.toml). Unset → built-in standard config, matching
# a default deployment.
if [[ -n "${EDGE_OPENVM_CONFIG:-}" ]]; then
  echo "Using custom OpenVM config: $EDGE_OPENVM_CONFIG" >&2
fi

exec cargo run \
  --manifest-path "$REPO_ROOT/Cargo.toml" \
  --release \
  --bin generate_edge_vm_vk \
  -- "$@"
