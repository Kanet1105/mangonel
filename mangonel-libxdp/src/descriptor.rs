use crate::umem::Umem;

/// A received frame's handle: where the packet lives in the
/// umem and how many bytes it occupies.
///
/// Only `XdpReceiver::receive` mints descriptors that refer
/// to a frame — the fields are crate-private and the type
/// is deliberately not `Clone`, so two live descriptors
/// never point at the same frame — and `XdpSender::send`
/// consumes them back to the empty state before the frame
/// re-enters circulation. Those rules make
/// [`Self::as_slice_mut`] sound: a minted descriptor is its
/// frame's sole handle, and the frame sits on no
/// ring — untouched by the kernel — while it stays minted.
#[derive(Debug, Default)]
pub struct XdpDescriptor {
    /// Offset of the packet data within the umem region.
    pub(crate) address: u64,
    /// Packet length in bytes.
    pub(crate) length: u32,
    /// Id of the umem whose receiver minted this
    /// descriptor; 0 for an empty
    /// one (default-constructed, or consumed). Lets the
    /// slice accessors reject a descriptor paired with
    /// the wrong umem, which would otherwise read —
    /// or alias a `&mut` into — an unrelated socket's
    /// frames. Ids are never reused, so a descriptor
    /// outliving its umem cannot be revalidated by a
    /// later umem mapping the same region.
    pub(crate) umem_id: usize,
    /// Recycle the frame instead of transmitting it; see
    /// [`Self::set_drop`].
    pub(crate) is_drop: bool,
}

impl XdpDescriptor {
    /// Packet length in bytes.
    ///
    /// Not necessarily the slice length: the slices also
    /// cover the frame headroom ahead of the packet.
    #[inline]
    pub fn length(&self) -> u32 {
        self.length
    }

    /// Panics unless this descriptor was minted against
    /// `umem` and still owns its frame. Zero can never
    /// match: umem ids start at 1.
    #[inline]
    fn check_minted_for(&self, umem: &Umem) {
        assert!(
            self.umem_id == umem.id(),
            "XdpDescriptor is not backed by this umem: it is empty (default-constructed or \
             already consumed), or was minted by a different socket's receiver."
        );
    }

    /// A shared view of the frame: the headroom followed by
    /// the packet.
    ///
    /// Borrows `self` as well as `umem`, so the descriptor
    /// cannot be passed to `send` — which would recycle
    /// the frame under this slice — while the slice is
    /// alive.
    ///
    /// # Panics
    ///
    /// Panics if this descriptor is empty (never minted, or
    /// already consumed) or was minted by a different
    /// socket's receiver.
    #[inline]
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

        // SAFETY: The mint check proves this descriptor came from
        // this umem's receiver and still owns its frame, so
        // the frame is on no ring and the kernel will not
        // write it; returning it to circulation goes through
        // send, which needs `&mut` on this descriptor and so is
        // excluded while this shared borrow lives. get_data
        // confirmed the range lies inside the region, which
        // the borrow of `umem` keeps mapped for 'a. Shared
        // views may alias freely.
        unsafe { std::slice::from_raw_parts(offset, length) }
    }

    /// An exclusive view of the frame: the headroom
    /// followed by the packet.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as
    /// [`Self::as_slice`].
    #[inline]
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

        // SAFETY: As above for the range, the mapping, and the
        // kernel staying off the frame. Exclusivity: a
        // minted descriptor is its frame's sole
        // handle — receive mints one per rx-ring entry and frame
        // addresses are in flight only once, the
        // crate-private fields and absent Clone leave
        // no way to forge or duplicate one, and send consumes it
        // before the frame re-enters circulation — and `&'a mut
        // self` locks this one for 'a.
        unsafe { std::slice::from_raw_parts_mut(offset, length) }
    }

    /// The packet alone, with the frame headroom skipped.
    ///
    /// [`Self::as_slice`] starts at the headroom, which is
    /// what a caller prepending headers wants; a caller
    /// parsing what arrived wants this.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as
    /// [`Self::as_slice`].
    #[inline]
    pub fn packet<'a>(&'a self, umem: &'a Umem) -> &'a [u8] {
        let headroom = umem.config().frame_headroom as usize;
        &self.as_slice(umem)[headroom..]
    }

    /// An exclusive view of the packet, with the frame
    /// headroom skipped.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as
    /// [`Self::as_slice`].
    #[inline]
    pub fn packet_mut<'a>(&'a mut self, umem: &'a Umem) -> &'a mut [u8] {
        let headroom = umem.config().frame_headroom as usize;
        &mut self.as_slice_mut(umem)[headroom..]
    }

    /// Marks this descriptor to be dropped:
    /// `XdpSender::send` returns its frame to the pool
    /// instead of transmitting it.
    pub fn set_drop(&mut self) {
        self.is_drop = true;
    }
}
