use crate::umem::Umem;

/// A received frame's handle. Not `Clone` and minted only
/// by `XdpReceiver::receive`, so a descriptor is its
/// frame's sole handle — what makes
/// [`Self::as_slice_mut`] sound. A descriptor that merely
/// goes out of scope leaks its frame.
#[derive(Debug, Default)]
pub struct XdpDescriptor {
    /// Offset of the frame within the umem area.
    address: u64,
    /// Frame length in bytes.
    length: u32,
    /// Indicate whether we want to drop the frame.
    is_drop: bool,
}

impl XdpDescriptor {
    pub(crate) fn new(address: u64, length: u32) -> Self {
        Self {
            address,
            length,
            is_drop: false,
        }
    }

    /// Offset of the frame within the umem area.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Frame length in bytes. The slices are longer: they
    /// include the headroom ahead of the frame.
    pub fn length(&self) -> u32 {
        self.length
    }

    /// Whether the frame is marked to return to the pool
    /// instead of being sent.
    pub fn is_drop(&self) -> bool {
        self.is_drop
    }

    /// Marks the frame to return to the pool instead of
    /// being sent. The mark cannot be cleared.
    pub fn set_drop(&mut self) {
        self.is_drop = true;
    }

    /// A shared view of the buffer: headroom, then the
    /// frame.
    pub fn as_slice(&self) -> &[u8] {
        let umem = Umem::global();
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

        // SAFETY: A descriptor owns its frame — on no ring,
        // kernel off it; send needs `&mut self` and is
        // excluded while the borrow lives.
        // get_data bounds the range; the global umem
        // stays mapped.
        unsafe { std::slice::from_raw_parts(offset, length) }
    }

    /// Exclusive [`Self::as_slice`].
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        let umem = Umem::global();
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
        // descriptor is its frame's sole handle and
        // `&mut self` locks it while the slice lives.
        unsafe { std::slice::from_raw_parts_mut(offset, length) }
    }

    /// The received bytes, headroom skipped;
    /// [`Self::as_slice`] includes it for prepending.
    pub fn data(&self) -> &[u8] {
        let headroom = Umem::global().config().frame_headroom as usize;

        &self.as_slice()[headroom..]
    }

    /// Exclusive [`Self::data`].
    pub fn data_mut(&mut self) -> &mut [u8] {
        let headroom = Umem::global().config().frame_headroom as usize;

        &mut self.as_slice_mut()[headroom..]
    }
}
