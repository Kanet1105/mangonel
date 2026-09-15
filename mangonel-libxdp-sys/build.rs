//! Generates the bindings from the libxdp headers installed
//! on this system.

use std::{env, path::PathBuf};

const WRAPPER: &str = "wrapper.h";
const HINT: &str = "run `just deps` to install the libxdp development headers";

fn main() {
    println!("cargo:rerun-if-changed={WRAPPER}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-lib=xdp");

    let bindings = bindgen::Builder::default()
        .header(WRAPPER)
        .allowlist_function("xsk_.*")
        .allowlist_function("xdp_.*")
        .allowlist_function("libxdp_.*")
        .allowlist_type("xsk_.*")
        .allowlist_type("xdp_.*")
        .allowlist_var("XSK_.*")
        .allowlist_var("XDP_.*")
        .derive_default(true)
        // The ring accessors are `static inline` in xsk.h, which bindgen skips
        // by default; libxdp exports them as real symbols, so they link.
        .generate_inline_functions(true)
        .layout_tests(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate();

    let bindings = match bindings {
        Ok(bindings) => bindings,
        Err(e) => panic!("generating libxdp bindings: {e} -- {HINT}"),
    };

    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is set by cargo"));
    bindings
        .write_to_file(out.join("bindings.rs"))
        .expect("writing bindings.rs");
}
