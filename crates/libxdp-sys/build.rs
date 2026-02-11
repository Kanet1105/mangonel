use bindgen::Builder;
use mangonel_util::system;
use std::{env, path::PathBuf};

const WRAPPER: &str = "wrapper.h";

fn main() {
    system::check_system_info().unwrap();
    let default_lib_paths = system::default_library_paths().unwrap();

    // Tell cargo where to find the static libraries
    for lib_path in default_lib_paths {
        println!("cargo::rustc-link-search=native={}", lib_path.display());
    }
    println!("cargo::rustc-link-lib=static=bpf");
    println!("cargo::rustc-link-lib=static=xdp");
    println!("cargo::rerun-if-changed={WRAPPER}");

    let default_include_paths = system::default_include_paths().unwrap();

    // Generate bindings with clang include paths
    let mut builder = Builder::default()
        .header(WRAPPER)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate_inline_functions(true);
    for include_path in default_include_paths {
        builder = builder.clang_arg(format!("-I{}", include_path.display()));
    }
    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Failed to write bindings");
}
