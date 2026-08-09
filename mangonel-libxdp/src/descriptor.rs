use crate::umem::Umem;

/// A received frame's handle: where the frame lives in the
/// umem and how many bytes it occupies.
///
/// Only `XdpReceiver::receive` mints descriptors; fields
/// are crate-private and the type is not `Clone`, so a
/// minted descriptor is its frame's sole handle, and
/// `XdpSender::send` consumes it before the frame
/// re-enters circulation. That is what makes
/// [`Self::as_slice_mut`] sound.
#[derive(Debug, Default)]
pub struct XdpDescriptor {
    /// Offset of the frame within the umem region.
    pub(crate) address: u64,
    /// Frame length in bytes.
    pub(crate) length: u32,
    /// Id of the minting umem; 0 when empty. Ids are never
    /// reused, so a stale descriptor cannot be
    /// revalidated by a later umem.
    pub(crate) umem_id: usize,
    /// Recycle instead of transmitting; see
    /// [`Self::set_drop`].
    pub(crate) is_drop: bool,
}

impl XdpDescriptor {
    /// Frame length in bytes. The slices are longer: they
    /// include the headroom ahead of the frame.
    pub fn length(&self) -> u32 {
        self.length
    }

    /// Panics unless this descriptor was minted against
    /// `umem` and still owns its frame. Zero never
    /// matches: umem ids start at 1.
    fn check_minted_for(&self, umem: &Umem) {
        assert!(
            self.umem_id == umem.id(),
            "XdpDescriptor is not backed by this umem: it is empty (default-constructed or \
             already consumed), or was minted against a different umem."
        );
    }

    /// A shared view of the buffer: headroom, then the
    /// frame.
    ///
    /// Borrowing `self` keeps the descriptor out of `send`
    /// while the slice lives.
    ///
    /// # Panics
    ///
    /// Panics if the descriptor is empty or from a
    /// different umem.
    pub fn as_slice<'a>(&'a self, umem: &'a Umem) -> &'a [u8] {
        self.check_minted_for(umem);
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

        // SAFETY: The mint check proves this descriptor still owns
        // its frame, so it sits on no ring and the kernel
        // stays off it; send needs `&mut self` and is
        // excluded while this borrow lives. get_data bounds the
        // range; the `umem` borrow keeps it mapped for 'a.
        unsafe { std::slice::from_raw_parts(offset, length) }
    }

    /// An exclusive view of the buffer: headroom, then the
    /// frame.
    ///
    /// # Panics
    ///
    /// As [`Self::as_slice`].
    pub fn as_slice_mut<'a>(&'a mut self, umem: &'a Umem) -> &'a mut [u8] {
        self.check_minted_for(umem);
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

        // SAFETY: As above; exclusivity holds because a minted
        // descriptor is its frame's sole handle and `&'a mut
        // self` locks it for 'a.
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
    pub fn data<'a>(&'a self, umem: &'a Umem) -> &'a [u8] {
        let headroom = umem.config().frame_headroom as usize;
        &self.as_slice(umem)[headroom..]
    }

    /// The received bytes, exclusive, headroom skipped.
    ///
    /// # Panics
    ///
    /// As [`Self::as_slice`].
    pub fn data_mut<'a>(&'a mut self, umem: &'a Umem) -> &'a mut [u8] {
        let headroom = umem.config().frame_headroom as usize;
        &mut self.as_slice_mut(umem)[headroom..]
    }

    /// `XdpSender::send` returns this frame to the pool
    /// instead of transmitting it.
    pub fn set_drop(&mut self) {
        self.is_drop = true;
    }
}
