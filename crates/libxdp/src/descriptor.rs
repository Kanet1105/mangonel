use crate::umem::Umem;
use mangonel_data_plane::payload::Payload;
use mangonel_libxdp_sys::xdp_desc;

#[derive(Clone, Debug)]
pub struct Descriptor {
    pub address: u64,
    pub length: u32,
    pub umem: Umem,
    pub drop: bool,
}

impl Payload for Descriptor {
    #[inline(always)]
    fn payload(&self) -> &[u8] {
        let headroom_size = self.umem.umem_config().frame_headroom;
        let address = self.address - headroom_size as u64;
        let length = self.length as u64 + headroom_size as u64;
        let offset = self.umem.get_data(address) as *mut u8;
        unsafe { std::slice::from_raw_parts_mut(offset, length as usize) }
    }

    #[inline(always)]
    fn payload_mut(&mut self) -> &mut [u8] {
        let headroom_size = self.umem.umem_config().frame_headroom;
        let address = self.address - headroom_size as u64;
        let length = self.length as u64 + headroom_size as u64;
        let offset = self.umem.get_data(address) as *mut u8;
        unsafe { std::slice::from_raw_parts_mut(offset, length as usize) }
    }

    #[inline(always)]
    fn is_drop(&self) -> bool {
        self.drop
    }
}

impl Descriptor {
    #[inline(always)]
    pub fn new(descriptor: &xdp_desc, umem: &Umem) -> Self {
        Self {
            address: descriptor.addr,
            length: descriptor.len,
            umem: umem.clone(),
            drop: false,
        }
    }
}
