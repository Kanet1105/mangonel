use std::fmt;

use crate::umem::Umem;

/// A received frame's owned handle. Not `Clone` and minted
/// only by `XdpSocket::receive`, so a live descriptor is
/// its frame's sole handle — what makes
/// [`Self::as_slice_mut`] sound. Recycling is explicit
/// ([`Self::drop`]); a descriptor that merely goes out of
/// scope leaks its frame.
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

    /// Empties without recycling: frame ownership has
    /// moved elsewhere.
    pub(crate) fn defuse(&mut self) {
        self.umem = None;
        self.address = 0;
        self.length = 0;
    }

    /// Returns the frame to its umem's pool; a no-op on an
    /// empty descriptor.
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
            // A live frame holds no pool slot, so room exists;
            // the spin covers another thread's open grant.
            std::hint::spin_loop();
        }
    }

    /// A shared view of the buffer: headroom, then the
    /// frame. Panics if the descriptor is empty.
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

        // SAFETY: A live descriptor owns its frame — on no
        // ring, kernel off it; send needs `&mut self` and is
        // excluded while the borrow lives. get_data bounds
        // the range; self's umem handle keeps it mapped.
        unsafe { std::slice::from_raw_parts(offset, length) }
    }

    /// Exclusive [`Self::as_slice`].
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

        // SAFETY: As as_slice; exclusivity holds because a
        // live descriptor is its frame's sole handle and
        // `&mut self` locks it while the slice lives.
        unsafe { std::slice::from_raw_parts_mut(offset, length) }
    }

    /// The received bytes, headroom skipped;
    /// [`Self::as_slice`] includes it for prepending.
    pub fn data(&self) -> &[u8] {
        let headroom = self.umem().config().frame_headroom as usize;

        &self.as_slice()[headroom..]
    }

    /// Exclusive [`Self::data`].
    pub fn data_mut(&mut self) -> &mut [u8] {
        let headroom = self.umem().config().frame_headroom as usize;

        &mut self.as_slice_mut()[headroom..]
    }
}
