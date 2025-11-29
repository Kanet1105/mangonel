use crate::umem::Umem;

#[derive(Clone, Debug, Default)]
pub struct Descriptor {
    pub address: u64,
    pub length: u32,
    pub drop: bool,
}

impl Descriptor {
    #[inline(always)]
    pub fn as_slice(&self, umem: &Umem) -> &[u8] {
        let headroom_size = umem.config().frame_headroom;
        let address = self.address - headroom_size as u64;
        let length = self.length as u64 + headroom_size as u64;
        let offset = umem.get_data(address) as *const u8;
        unsafe { std::slice::from_raw_parts(offset, length as usize) }
    }

    #[inline(always)]
    pub fn as_slice_mut(&mut self, umem: &Umem) -> &mut [u8] {
        let headroom_size = umem.config().frame_headroom;
        let address = self.address - headroom_size as u64;
        let length = self.length as u64 + headroom_size as u64;
        let offset = umem.get_data(address) as *mut u8;
        unsafe { std::slice::from_raw_parts_mut(offset, length as usize) }
    }
}
