use std::{env, path::PathBuf};

use bindgen::Builder;

const LIB_NAME: &str = "libxdp";
const LIB_VERSION: &str = "1.4.0";
const WRAPPER: &str = "wrapper.h";

fn check_os() {
    if !cfg!(target_os = "linux") {
        panic!("Currently supports linux only.");
    }
}

/// Link a library by its name and version.
fn link_library(name: &str, version: &str) {
    println!("cargo::rerun-if-changed={}", WRAPPER);

    if cfg!(target_os = "linux") {
        println!("cargo::rustc-link-search=/usr/local/lib/");
        println!("cargo::rustc-link-lib={}.so.{}", name, version);
    }
}

fn main() {
    check_os();
    link_library(LIB_NAME, LIB_VERSION);

    let bindings = Builder::default()
        .header(WRAPPER)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate_inline_functions(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write bindings");
}
