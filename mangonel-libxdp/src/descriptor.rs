use crate::umem::Umem;

/// The address of a descriptor holding no frame; no frame
/// lies there.
const EMPTY: u64 = u64::MAX;

/// A received frame's handle, or empty. Not `Clone`,
/// minted only by `XdpSocket::receive` and emptied by
/// `send` and `drop`, so a descriptor is its frame's sole
/// handle — what makes [`Self::as_slice_mut`] sound. One
/// that goes out of scope holding a frame leaks it.
#[derive(Debug)]
pub struct XdpDescriptor {
    /// Offset of the frame within the umem area.
    address: u64,
    /// Frame length in bytes.
    length: u32,
}

/// Empty: holds no frame, so `send` and `drop` skip it.
impl Default for XdpDescriptor {
    fn default() -> Self {
        Self {
            address: EMPTY,
            length: 0,
        }
    }
}

impl XdpDescriptor {
    pub(crate) fn new(address: u64, length: u32) -> Self {
        Self { address, length }
    }

    /// Whether the descriptor holds no frame.
    pub fn is_empty(&self) -> bool {
        self.address == EMPTY
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

    /// A shared view of the buffer: headroom, then the
    /// frame. Panics if empty.
    pub fn as_slice(&self) -> &[u8] {
        assert!(
            !self.is_empty(),
            "XdpDescriptor is empty: its frame was sent or dropped."
        );
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
        // kernel off it; send and drop take it out of its
        // slot through `&mut`, excluded while the borrow
        // lives.
        // get_data bounds the range; the global umem
        // stays mapped.
        unsafe { std::slice::from_raw_parts(offset, length) }
    }

    /// Exclusive [`Self::as_slice`].
    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        assert!(
            !self.is_empty(),
            "XdpDescriptor is empty: its frame was sent or dropped."
        );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty() {
        assert!(XdpDescriptor::default().is_empty());
        assert!(!XdpDescriptor::new(0, 64).is_empty());
    }

    #[test]
    #[should_panic(expected = "XdpDescriptor is empty")]
    fn empty_has_no_slice() {
        let _ = XdpDescriptor::default().as_slice();
    }
}
