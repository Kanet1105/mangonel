use std::{env, path::PathBuf};

use bindgen::Builder;

const LIBBPF_PATH: &str = "xdp-tools/lib/libbpf/src";
const LIBBPF: &str = "bpf";
const LIBXDP_PATH: &str = "xdp-tools/lib/libxdp";
const LIBXDP: &str = "xdp";
const WRAPPER: &str = "wrapper.h";

fn check_os() {
    if !cfg!(target_os = "linux") {
        panic!("Currently supports linux only.");
    }
}

fn main() {
    check_os();
    println!("cargo::rustc-link-search={}", LIBBPF_PATH);
    println!("cargo::rustc-link-lib=static={}", LIBBPF);
    println!("cargo::rustc-link-search={}", LIBXDP_PATH);
    println!("cargo::rustc-link-lib=static={}", LIBXDP);
    println!("cargo::rerun-if-changed={}", WRAPPER);

    let bindings = Builder::default()
        .header(WRAPPER)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate_inline_functions(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    println!("{:?}", out_path);
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write bindings");
}
