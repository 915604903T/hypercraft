use alloc::{sync::Arc, vec, vec::Vec};
use spin::Mutex;
use crate::HyperResult;

pub trait PortIoDevice: Send + Sync {
    fn port_range(&self) -> core::ops::Range<u16>;
    fn read(&mut self, port: u16, access_size: u8) -> HyperResult<u32>;
    fn write(&mut self, port: u16, access_size: u8, value: u32) -> HyperResult;
}

pub struct Devices {
    pub port_io_devices: Vec<Arc<Mutex<dyn PortIoDevice>>>,
}
