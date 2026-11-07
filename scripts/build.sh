#!/usr/bin/env bash
# Test every crate, then build the release binaries.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo test --workspace
cargo build --release
