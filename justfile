# Display available commands
default:
    @just --list

# Install the libxdp/libbpf headers and the libclang bindgen needs
deps:
    #!/usr/bin/env bash
    set -euo pipefail

    if [ ! -r /etc/os-release ]; then
        echo "no /etc/os-release to identify this system" >&2
        exit 1
    fi
    . /etc/os-release

    sudo=""
    if [ "$(id -u)" -ne 0 ]; then
        sudo="sudo"
    fi

    # ID names the distro and ID_LIKE its upstream, so matching both covers
    # derivatives -- Mint, Pop!_OS, Rocky, Manjaro -- without naming them. The
    # surrounding spaces keep "suse" from matching inside another word.
    case " ${ID:-} ${ID_LIKE:-} " in
        *" debian "*|*" ubuntu "*)
            $sudo apt-get update
            $sudo apt-get install -y libxdp-dev libbpf-dev libclang-dev
            ;;
        *" fedora "*|*" rhel "*|*" centos "*)
            if command -v dnf >/dev/null; then pm=dnf; else pm=yum; fi
            $sudo "$pm" install -y libxdp-devel libbpf-devel clang-devel
            ;;
        *" arch "*)
            $sudo pacman -S --needed --noconfirm libxdp libbpf clang
            ;;
        *" suse "*|*" opensuse "*)
            $sudo zypper install -y libxdp-devel libbpf-devel clang-devel
            ;;
        *" alpine "*)
            $sudo apk add libxdp-dev libbpf-dev clang-dev
            ;;
        *)
            echo "unrecognised distro '${ID:-?}'; install the libxdp headers by hand" >&2
            exit 1
            ;;
    esac

    # The package manager reporting success is not the same as the headers
    # being usable: distros before libxdp was split out of xdp-tools ship no
    # such package, and some ship the library without the -dev half. Check for
    # the same header mangonel-libxdp-sys/build.rs looks for, rather than asking
    # pkg-config, which is a separate package and not what the build consults.
    if [ ! -r /usr/include/xdp/xsk.h ] && [ ! -r /usr/local/include/xdp/xsk.h ]; then
        echo "installed, but no xdp/xsk.h -- this distro may predate the libxdp" >&2
        echo "package; build xdp-tools from source instead" >&2
        exit 1
    fi
    echo "libxdp headers ready"

# Build all crates
build:
    cargo test --workspace
    cargo build --release

# Run the veth smoke tests, which need root to create links
# and bind AF_XDP. Built first as the invoking user so the
# compiler cache is not left root-owned.
smoke:
    cargo test -p mangonel --no-run
    # Absolute path to cargo: sudo's secure_path drops the rustup
    # PATH, and -E preserves HOME so the toolchain still resolves.
    sudo -E "$(command -v cargo)" test -p mangonel -- --ignored --test-threads=1 --nocapture

# Lint with clippy
lint:
    cargo sort --workspace -g
    cargo +nightly fmt
    cargo clippy --release
