use std::fmt;

use crate::umem::Umem;

/// A received frame's owned handle: which umem the frame
/// lives in, where, and how many bytes it occupies.
///
/// Only `XdpSocket::receive` mints descriptors; fields are
/// crate-private and the type is not `Clone`, so a minted
/// descriptor is its frame's sole handle, and
/// `XdpSocket::send` consumes it before the frame re-enters
/// circulation. That is what makes [`Self::as_slice_mut`]
/// sound.
///
/// The descriptor holds a handle to its umem, so it can
/// move freely — into queues, tables, across threads —
/// without a paired umem reference, and it cannot outlive
/// the mapping. Recycling is explicit: [`Self::drop`]
/// returns the frame to the pool, and a descriptor that
/// merely goes out of scope leaks its frame — the cost of
/// letting the owner decide when, and on which thread, a
/// frame returns.
#[derive(Default)]
pub struct XdpDescriptor {
    /// The minting umem; `None` when empty
    /// (default-constructed or already consumed).
    pub(crate) umem: Option<Umem>,
    /// Offset of the frame within the umem region.
    pub(crate) address: u64,
    /// Frame length in bytes.
    pub(crate) length: u32,
}

impl fmt::Debug for XdpDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XdpDescriptor")
            .field("address", &self.address)
            .field("length", &self.length)
            .field("live", &self.umem.is_some())
            .finish()
    }
}

impl XdpDescriptor {
    /// Frame length in bytes. The slices are longer: they
    /// include the headroom ahead of the frame.
    pub fn length(&self) -> u32 {
        self.length
    }

    /// Panics unless this descriptor still owns its frame.
    fn umem(&self) -> &Umem {
        self.umem
            .as_ref()
            .expect("XdpDescriptor is empty: default-constructed or already consumed.")
    }

    /// Empties the descriptor without recycling: ownership
    /// of the frame has moved elsewhere — a tx ring or a
    /// pool grant.
    pub(crate) fn defuse(&mut self) {
        self.umem = None;
        self.address = 0;
        self.length = 0;
    }

    /// Returns the frame to its umem's pool, consuming the
    /// descriptor; an empty descriptor is a no-op. Any
    /// owner on any thread may call this — a pipeline
    /// stage that filters frames drops them here without
    /// routing them through `send`.
    pub fn drop(mut self) {
        let Some(umem) = self.umem.take() else {
            return;
        };

        let pool = umem.pool();
        loop {
            if let Some((_, index)) = pool.claim_write(1) {
                pool.write_at(index as usize, self.address);
                pool.commit_write(index as usize, 1);

                return;
            }
            // A live frame holds no pool slot, so room exists; the
            // spin only covers another thread's grant between
            // claim and commit.
            std::hint::spin_loop();
        }
    }

    /// A shared view of the buffer: headroom, then the
    /// frame.
    ///
    /// Borrowing `self` keeps the descriptor out of `send`
    /// while the slice lives.
    ///
    /// # Panics
    ///
    /// Panics if the descriptor is empty.
    pub fn as_slice(&self) -> &[u8] {
        let umem = self.umem();
        let headroom_size = umem.config().frame_headroom;
        let length = self.length as usize + headroom_size as usize;
        let address = self
            .address
            .checked_sub(u64::from(headroom_size))
            .expect("XdpDescriptor address lies below its frame headroom. This is a bug.");
        let offset = umem
            .get_data(address, length)
            .expect("XdpDescriptor range falls outside the umem region. This is a bug.")
            .cast::<u8>();

        // SAFETY: A live descriptor still owns its frame, so it
        // sits on no ring and the kernel stays off it; send
        // needs `&mut self` and is excluded while this
        // borrow lives. get_data bounds the range; the umem
        // handle held by self keeps it mapped.
        unsafe { std::slice::from_raw_parts(offset, length) }
    }

    /// An exclusive view of the buffer: headroom, then the
    /// frame.
    ///
    /// # Panics
    ///
    /// As [`Self::as_slice`].
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        let umem = self.umem();
        let headroom_size = umem.config().frame_headroom;
        let length = self.length as usize + headroom_size as usize;
        let address = self
            .address
            .checked_sub(u64::from(headroom_size))
            .expect("XdpDescriptor address lies below its frame headroom. This is a bug.");
        let offset = umem
            .get_data(address, length)
            .expect("XdpDescriptor range falls outside the umem region. This is a bug.")
            .cast::<u8>();

        // SAFETY: As above; exclusivity holds because a live
        // descriptor is its frame's sole handle and `&mut
        // self` locks it while the slice lives.
        unsafe { std::slice::from_raw_parts_mut(offset, length) }
    }

    /// The received bytes — the frame, headroom skipped.
    /// What a caller parsing what arrived wants;
    /// [`Self::as_slice`] starts at the headroom
    /// instead, for a caller prepending.
    ///
    /// # Panics
    ///
    /// As [`Self::as_slice`].
    pub fn data(&self) -> &[u8] {
        let headroom = self.umem().config().frame_headroom as usize;

        &self.as_slice()[headroom..]
    }

    /// The received bytes, exclusive, headroom skipped.
    ///
    /// # Panics
    ///
    /// As [`Self::as_slice`].
    pub fn data_mut(&mut self) -> &mut [u8] {
        let headroom = self.umem().config().frame_headroom as usize;

        &mut self.as_slice_mut()[headroom..]
    }
}
