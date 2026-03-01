# Display available commands
default:
    @just --list

# Build all crates
build:
    cargo test --workspace
    cargo build --release

# Lint with clippy
lint:
    cargo machete
    cargo sort --workspace -g
    cargo +nightly fmt
    cargo clippy --release