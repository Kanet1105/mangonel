//! What the pipeline needs of a frame, so it runs on umem
//! frames in a worker and on plain buffers in tests.

use mangonel_libxdp::XdpDescriptor;

/// One frame: the packet's bytes, in a buffer that can hold
/// more.
pub(crate) trait Frame {
    /// The packet.
    fn data_mut(&mut self) -> &mut [u8];

    /// The longest packet the buffer holds.
    fn capacity(&self) -> usize;

    /// Makes the packet `length` bytes long, at most
    /// [`Self::capacity`]. Bytes gained hold whatever the
    /// buffer last did, so write every one.
    fn set_length(&mut self, length: usize);
}

impl Frame for XdpDescriptor {
    fn data_mut(&mut self) -> &mut [u8] {
        XdpDescriptor::data_mut(self)
    }

    fn capacity(&self) -> usize {
        XdpDescriptor::capacity(self) as usize
    }

    fn set_length(&mut self, length: usize) {
        let length = u32::try_from(length)
            .expect("A length within a frame's capacity fits a u32. This is a bug.");

        XdpDescriptor::set_length(self, length);
    }
}

/// Frames a pass produced, for the worker to send or
/// return.
pub(crate) struct Output<F> {
    /// To send, by egress port.
    pub(crate) send: Vec<Vec<F>>,
    /// To return to the pool unsent.
    pub(crate) drop: Vec<F>,
}

impl<F> Output<F> {
    /// An empty output for `ports` ports.
    pub(crate) fn new(ports: usize) -> Self {
        Self {
            send: (0..ports).map(|_| Vec::new()).collect(),
            drop: Vec::new(),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// What a test buffer holds at most.
    const CAPACITY: usize = 2048;

    /// A frame on the heap. Growing it fills the new bytes
    /// with junk, as a umem frame's stale contents would.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct Buffer(pub(crate) Vec<u8>);

    impl Frame for Buffer {
        fn data_mut(&mut self) -> &mut [u8] {
            &mut self.0
        }

        fn capacity(&self) -> usize {
            CAPACITY
        }

        fn set_length(&mut self, length: usize) {
            assert!(
                length <= CAPACITY,
                "{length} bytes do not fit a test buffer"
            );
            self.0.resize(length, 0xA5);
        }
    }
}
