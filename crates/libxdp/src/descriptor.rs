use crate::umem::Umem;
use mangonel_libxdp_sys::xdp_desc;

#[derive(Clone, Debug)]
pub struct Descriptor {
    pub address: u64,
    pub length: u32,
    pub umem: Umem,
    pub drop: bool,
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

    #[inline(always)]
    pub fn get_data_mut(&mut self) -> &mut [u8] {
        let headroom_size = self.umem.umem_config().frame_headroom;
        let address = self.address - headroom_size as u64;
        let length = self.length as u64 + headroom_size as u64;
        let offset = self.umem.get_data(address) as *mut u8;
        unsafe { std::slice::from_raw_parts_mut(offset, length as usize) }
    }
}
