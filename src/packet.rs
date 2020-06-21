//! The packet forwarded to userspace on VM Exits.

use core::fmt::{Debug, Formatter, Result};

#[repr(u32)]
#[derive(Debug)]
#[allow(dead_code)]
pub enum RvmExitPacketKind {
    GuestIo = 1,
    GuestMmio = 2,
    GuestVcpu = 3,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IoPacket {
    pub port: u16,
    pub access_size: u8,
    pub input: bool,
    pub string: bool,
    pub repeat: bool,
}

#[repr(C)]
#[derive(Debug)]
pub struct MmioPacket {
    pub addr: u64,
}

#[repr(C)]
union RvmExitPacketInnner {
    io: IoPacket,
    mmio: MmioPacket,
}

#[repr(C)]
pub struct RvmExitPacket {
    kind: RvmExitPacketKind,
    key: u64,
    inner: RvmExitPacketInnner,
}

impl RvmExitPacket {
    pub fn new_io_packet(key: u64, io_packet: IoPacket) -> Self {
        Self {
            kind: RvmExitPacketKind::GuestIo,
            key,
            inner: RvmExitPacketInnner { io: io_packet },
        }
    }
}

impl Debug for RvmExitPacket {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let mut out = f.debug_struct("RvmExitPacket");
        out.field("kind", &self.kind).field("key", &self.key);
        unsafe {
            match self.kind {
                RvmExitPacketKind::GuestIo => out.field("inner", &self.inner.io),
                RvmExitPacketKind::GuestMmio => out.field("inner", &self.inner.mmio),
                _ => out.field("inner", &"Unknown"),
            };
        }
        out.finish()
    }
}
