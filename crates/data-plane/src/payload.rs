pub trait Payload: Copy {
    fn payload(&self) -> &[u8];

    fn payload_mut(&mut self) -> &mut [u8];
}
