use mangonel_libxdp_sys::xdp_desc;

use crate::socket::Socket;

#[derive(Clone, Copy, Debug, Default)]
pub struct Descriptor {
    address: u64,
    length: u32,
}

impl From<&xdp_desc> for Descriptor {
    fn from(value: &xdp_desc) -> Self {
        Self {
            address: value.addr,
            length: value.len,
        }
    }
}

impl Descriptor {
    #[inline(always)]
    pub fn address(&self) -> u64 {
        self.address
    }

    #[inline(always)]
    pub fn length(&self) -> u32 {
        self.length
    }

    #[inline(always)]
    pub fn get_data(&mut self, socket: &Socket) -> &mut [u8] {
        let headroom_size = socket.umem().umem_config().frame_headroom;
        let address = self.address - headroom_size as u64;
        let length = self.length as u64 + headroom_size as u64;
        let offset = socket.umem().get_data(address) as *mut u8;

        unsafe { std::slice::from_raw_parts_mut(offset, length as usize) }
    }
}
