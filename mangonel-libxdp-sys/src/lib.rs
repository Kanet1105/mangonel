//! Raw FFI bindings to the libxdp installed on this system.
//!
//! Generated at build time from the system headers, so what
//! is declared here matches the libxdp actually installed
//! rather than a vendored snapshot. Run `just deps` if the
//! build cannot find the headers.
//!
//! `build.rs` configures no search paths of its own:
//! `xdp/xsk.h` is found through clang's default include
//! path and `-lxdp` through the linker's, both
//! of which already cover the distro locations. A libxdp
//! installed outside them needs `-I` via
//! `BINDGEN_EXTRA_CLANG_ARGS` and `-L` via `RUSTFLAGS`.
//!
//! This crate is the unsafe, one-to-one layer and adds
//! nothing of its own; the safe wrappers live in
//! `mangonel-libxdp`.
//!
//! # Inline functions
//!
//! Much of `xsk.h` is `static inline` — the ring accessors
//! (`xsk_ring_prod__*`, `xsk_ring_cons__*`) and the UMEM
//! address arithmetic among them. bindgen skips
//! those by default because a `static inline` definition
//! normally leaves no symbol to link against, but libxdp
//! compiles and exports them anyway, so
//! `generate_inline_functions` in `build.rs` binds them and
//! they link like any other function.
//!
//! That is load-bearing: `mangonel-libxdp` drives the rings
//! through exactly these helpers. If a future libxdp stops
//! exporting them, the failure is a link error naming the
//! symbol, and the fix is bindgen's `--wrap-static-fns`.

// Generated code follows C's naming and is not ours to lint. pedantic is
// allowed alongside `all` because the workspace's cast lints live in that
// group, which `clippy::all` does not cover.
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
#![allow(dead_code)]
#![allow(clippy::all, clippy::pedantic)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use std::{ffi::CStr, os::raw::c_char};

    use super::*;

    /// Proves the crate reaches a real libxdp, which
    /// compiling alone does not: the struct layouts are
    /// checked at compile time by the generated `const`
    /// assertions, but only calling a symbol exercises the
    /// link.
    ///
    /// `libxdp_strerror` is the one entry point with
    /// nothing to set up and no side effects — it just
    /// formats an errno.
    #[test]
    fn links_against_libxdp() {
        let mut buf = [0 as c_char; 128];
        unsafe { libxdp_strerror(22, buf.as_mut_ptr(), buf.len()) };
        let msg = unsafe { CStr::from_ptr(buf.as_ptr()) };
        assert!(!msg.to_bytes().is_empty(), "libxdp_strerror wrote nothing");
    }
}
