//! Stopping on SIGINT and SIGTERM.

use std::{
    io,
    mem,
    ptr,
    sync::atomic::{
        AtomicBool,
        Ordering,
    },
};

/// Set once a signal asks the daemon to stop.
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn stop(_signal: libc::c_int) {
    // Nothing is ordered against the flag; the main thread
    // polls it.
    STOP.store(true, Ordering::Relaxed);
}

/// Makes SIGINT and SIGTERM ask for a stop, which
/// [`requested`] then reports, where they would have killed
/// the process with its sockets still bound.
pub(crate) fn install() -> io::Result<()> {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: All zeroes is a valid sigaction: no flags
        // and an empty mask, with the handler set below.
        let mut action: libc::sigaction = unsafe { mem::zeroed() };
        action.sa_sigaction = stop as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // SAFETY: The action is initialized and outlives the
        // call, the old one is not asked for, and the
        // handler only stores to an atomic, which is
        // async-signal-safe.
        if unsafe { libc::sigaction(signal, &action, ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

/// Whether a signal has asked the daemon to stop.
pub(crate) fn requested() -> bool {
    STOP.load(Ordering::Relaxed)
}
