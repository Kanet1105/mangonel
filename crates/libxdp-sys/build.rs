use bindgen::Builder;
use std::{env, fs, os::unix, path::PathBuf};

const XDP_TOOLS: &str = "../../xdp-tools";
const LIBBPF: &str = "lib/libbpf/src";
const LIBXDP: &str = "lib/libxdp";
const WRAPPER: &str = "wrapper.h";

fn check_os() {
    if !cfg!(target_os = "linux") {
        panic!("Currently supports linux only.");
    }
}

fn main() {
    check_os();

    let package_root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let xdp_tools = package_root.join(XDP_TOOLS).canonicalize().expect(
        "xdp-tools directory not found - did you run `git submodule update --init --recursive`?",
    );
    let libbpf = xdp_tools.join(LIBBPF);
    let libxdp = xdp_tools.join(LIBXDP);
    let headers_path = xdp_tools.join("headers");

    // Create a symlink bpf -> libbpf/src in headers/ so that <bpf/libbpf.h> resolves correctly
    // xsk.h includes <bpf/libbpf.h> which expects headers/bpf/libbpf.h
    let bpf_symlink = headers_path.join("bpf");
    if !bpf_symlink.join("libbpf.h").exists() {
        // Remove existing bpf directory/symlink if it doesn't have libbpf.h
        let _ = fs::remove_dir_all(&bpf_symlink);
        let _ = fs::remove_file(&bpf_symlink);
        unix::fs::symlink(&libbpf, &bpf_symlink)
            .expect("Failed to create bpf symlink in headers directory");
    }

    // Tell cargo where to find the static libraries
    println!("cargo::rustc-link-search=native={}", libbpf.display());
    println!("cargo::rustc-link-lib=static=bpf");
    println!("cargo::rustc-link-search=native={}", libxdp.display());
    println!("cargo::rustc-link-lib=static=xdp");
    println!("cargo::rerun-if-changed={WRAPPER}");

    // Generate bindings with clang include paths
    let bindings = Builder::default()
        .header(WRAPPER)
        // Include path for <xdp/xsk.h>, <xdp/libxdp.h>, and <bpf/libbpf.h> (via symlink)
        .clang_arg(format!("-I{}", headers_path.display()))
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate_inline_functions(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write bindings");
}
