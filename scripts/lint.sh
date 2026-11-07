#!/usr/bin/env bash
# Sort Cargo.toml dependencies, format with nightly rustfmt, then run clippy.
# This rewrites files; it is not a check-only pass.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo sort --workspace -g
cargo +nightly fmt
cargo clippy --release
