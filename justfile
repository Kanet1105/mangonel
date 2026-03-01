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


# Install libxdp headers (auto-detects distro)
deps:
    #!/usr/bin/env bash
    set -euo pipefail

    distro=$(. /etc/os-release && echo "${ID_LIKE:-$ID}")
    echo "Detected distro: $distro"

    case "$distro" in
        *debian* | *ubuntu*) sudo apt-get install -y libxdp-dev   ;;
        *fedora* | *rhel*)   sudo dnf install -y libxdp-devel     ;;
        *arch*)              sudo pacman -S --needed libxdp       ;;
        *)                   echo "Unsupported distro: $distro"
                             exit 1                               ;;
    esac