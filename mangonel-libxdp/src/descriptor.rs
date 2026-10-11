use std::{fmt, ptr::NonNull};

use crate::umem::UmemShared;

/// A received frame's owned handle. Not `Clone` and minted
/// only by `XdpReceiver::receive`, so a live descriptor is
/// its frame's sole handle — what makes
/// [`Self::as_slice_mut`] sound. Recycling is explicit
/// ([`Self::drop`], [`Self::drop_all`]); a descriptor that
/// merely goes out of scope leaks its frame, and keeps its
/// umem's memory mapped for good.
#[derive(Default)]
pub struct XdpDescriptor {
    /// The minting umem; `None` when empty
    /// (default-constructed or already consumed). Not
    /// reference counted: a live descriptor is counted in
    /// the umem's `outstanding` instead, which keeps this
    /// pointer valid until the descriptor is consumed.
    pub(crate) umem: Option<NonNull<UmemShared>>,
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

// SAFETY: The pointee is `Send + Sync` and stays allocated
// while the descriptor is live (see `UmemShared`); the
// frame itself is owned by this descriptor alone, so
// moving it moves that ownership.
unsafe impl Send for XdpDescriptor {}

// SAFETY: `&self` reaches the frame only through
// `as_slice`, a shared read, and the umem only through
// `&UmemShared`, which is `Sync`.
unsafe impl Sync for XdpDescriptor {}

impl XdpDescriptor {
    /// Frame length in bytes. The slices are longer: they
    /// include the headroom ahead of the frame.
    pub fn length(&self) -> u32 {
        self.length
    }

    /// Panics unless this descriptor still owns its frame.
    fn umem(&self) -> &UmemShared {
        let umem = self
            .umem
            .expect("XdpDescriptor is empty: default-constructed or already consumed.");

        // SAFETY: A live descriptor is counted in its
        // umem's `outstanding`, so the umem is not freed
        // before the descriptor is consumed, and consuming
        // needs `self` or `&mut self`.
        unsafe { umem.as_ref() }
    }

    /// Empties without recycling: frame ownership has
    /// moved elsewhere.
    pub(crate) fn defuse(&mut self) {
        self.umem = None;
        self.address = 0;
        self.length = 0;
    }

    /// Returns the frame to its umem's pool; a no-op on an
    /// empty descriptor. Prefer [`Self::drop_all`] for a
    /// batch: it touches the pool and the umem's counter
    /// once per run of same-umem descriptors, not once per
    /// frame.
    pub fn drop(mut self) {
        Self::drop_all(std::slice::from_mut(&mut self));
    }

    /// Returns every live frame in `buffer` to its umem's
    /// pool and leaves each slot empty, ready to receive
    /// into. Empty slots are skipped, and descriptors from
    /// different umems may be mixed.
    pub fn drop_all(buffer: &mut [XdpDescriptor]) {
        let mut start = 0;
        while start < buffer.len() {
            let Some(umem) = buffer[start].umem else {
                start += 1;

                continue;
            };

            // The run: every slot up to the first live one
            // from another umem.
            let mut end = start;
            let mut count: u32 = 0;
            while let Some(descriptor) = buffer.get(end) {
                match descriptor.umem {
                    Some(other) if other != umem => break,
                    Some(_) => count += 1,
                    None => {}
                }
                end += 1;
            }

            // SAFETY: The run's descriptors are live until
            // the reclaim below, which is the last access.
            let shared = unsafe { umem.as_ref() };
            let pool = shared.pool();
            let index = pool.claim_write_all(count);
            let mut written: u32 = 0;
            for descriptor in &mut buffer[start..end] {
                if descriptor.umem.is_some() {
                    pool.write_at(index.wrapping_add(written) as usize, descriptor.address);
                    written += 1;
                    descriptor.defuse();
                }
            }
            pool.commit_write(index as usize, count);
            shared.reclaim(count);

            start = end;
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
        // ring, kernel off it; send needs `&mut self` and
        // is excluded while the borrow lives.
        // get_data bounds the range; self's umem
        // handle keeps it mapped.
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

#[cfg(test)]
mod tests {
    use std::ptr::NonNull;

    use super::XdpDescriptor;
    use crate::umem::{
        UmemShared,
        tests::{outstanding, release, shared},
    };

    /// Takes `count` frames out of the pool and mints them,
    /// as a socket's receive would.
    fn mint(umem: NonNull<UmemShared>, count: u32) -> Vec<XdpDescriptor> {
        let view = unsafe { umem.as_ref() };
        let pool = view.pool();
        let (granted, index) = pool.claim_read(count).unwrap();
        assert_eq!(granted, count);
        view.lend(count);
        let descriptors = (0..count)
            .map(|offset| XdpDescriptor {
                umem: Some(umem),
                address: pool.read_at(index.wrapping_add(offset) as usize),
                length: 64,
            })
            .collect();
        pool.commit_read(index as usize, count);

        descriptors
    }

    /// Frames currently in the pool, put back afterwards.
    fn pooled(umem: NonNull<UmemShared>) -> u32 {
        let pool = unsafe { umem.as_ref() }.pool();
        let Some((count, index)) = pool.claim_read(u32::MAX) else {
            return 0;
        };
        let addresses: Vec<u64> = (0..count)
            .map(|offset| pool.read_at(index.wrapping_add(offset) as usize))
            .collect();
        pool.commit_read(index as usize, count);
        let index = pool.claim_write_all(count);
        for (offset, address) in (0..count).zip(addresses) {
            pool.write_at(index.wrapping_add(offset) as usize, address);
        }
        pool.commit_write(index as usize, count);

        count
    }

    #[test]
    fn drop_all_returns_frames_and_settles_the_count() {
        let umem = shared(8);
        let mut batch = mint(umem, 5);
        batch.insert(2, XdpDescriptor::default());
        assert_eq!(outstanding(umem), 5);
        assert_eq!(pooled(umem), 3);

        XdpDescriptor::drop_all(&mut batch);
        assert!(batch.iter().all(|descriptor| descriptor.umem.is_none()));
        assert_eq!(outstanding(umem), 0);
        assert_eq!(pooled(umem), 8);
        assert!(release(umem));
    }

    #[test]
    fn drop_all_splits_runs_by_umem() {
        let (a, b) = (shared(4), shared(4));
        let mut from_a = mint(a, 3).into_iter();
        let mut from_b = mint(b, 2).into_iter();
        let mut batch = vec![
            from_a.next().unwrap(),
            from_b.next().unwrap(),
            from_a.next().unwrap(),
            from_a.next().unwrap(),
            from_b.next().unwrap(),
        ];

        XdpDescriptor::drop_all(&mut batch);
        assert_eq!((outstanding(a), outstanding(b)), (0, 0));
        assert_eq!((pooled(a), pooled(b)), (4, 4));
        assert!(release(a) && release(b));
    }

    #[test]
    fn a_forgotten_descriptor_keeps_its_umem_alive() {
        let umem = shared(4);
        let mut batch = mint(umem, 2);
        let kept = batch.pop().unwrap();
        XdpDescriptor::drop_all(&mut batch);

        assert!(!release(umem));
        // Still readable after the last socket would have
        // gone: the umem leaked rather than unmapping.
        assert_eq!(kept.data().len(), 64);
        kept.drop();
        assert_eq!(outstanding(umem), 0);
    }
}
