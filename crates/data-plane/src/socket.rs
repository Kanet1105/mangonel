use crate::payload::Payload;
use std::iter::Iterator;

pub trait SocketRx: Send + 'static {
    fn read_iter(&mut self) -> impl Iterator<Item = impl Payload>;
}

pub trait SocketTx: Send + 'static {
    fn write_iter(&mut self, iter: impl Iterator<Item = impl Payload>);
}
