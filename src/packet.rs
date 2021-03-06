//! The packet forwarded to userspace on VM Exits.

use core::fmt::{Debug, Formatter, Result};

#[repr(u32)]
#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum RvmExitPacketKind {
    GuestBell = 1,
    GuestIo = 2,
    GuestMmio = 3,
    GuestVcpu = 4,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct BellPacket {
    pub addr: u64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
pub struct IoPacket {
    pub port: u16,
    pub access_size: u8,
    pub input: bool,
    pub string: bool,
    pub repeat: bool,
    pub _padding1: [u8; 2],
    pub data: [u8; 4],
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Default)]
pub struct MmioPacket {
    pub addr: u64,
    pub inst_len: u8,
    pub inst_buf: [u8; 15],
    pub default_operand_size: u8,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Default)]
pub struct MmioPacket {
    pub addr: u64,
    pub access_size: u8,
    pub sign_extend: bool,
    pub xt: u8,
    pub read: bool,
    pub _padding1: [u8; 4],
    pub data: u64,
}

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
#[repr(C)]
#[derive(Debug, Default)]
pub struct MmioPacket {
    pub addr: u64,
    pub access_size: u8,
    pub read: bool,
    pub data: u64
}

#[repr(C)]
pub union RvmExitPacketInnner {
    pub bell: BellPacket,
    pub io: IoPacket,
    pub mmio: MmioPacket,
}

#[repr(C)]
pub struct RvmExitPacket {
    pub kind: RvmExitPacketKind,
    pub key: u64,
    pub inner: RvmExitPacketInnner,
}

impl RvmExitPacket {
    pub fn new_bell_packet(key: u64, addr: u64) -> Self {
        Self {
            kind: RvmExitPacketKind::GuestBell,
            key,
            inner: RvmExitPacketInnner {
                bell: BellPacket { addr },
            },
        }
    }

    pub fn new_io_packet(key: u64, io_packet: IoPacket) -> Self {
        Self {
            kind: RvmExitPacketKind::GuestIo,
            key,
            inner: RvmExitPacketInnner { io: io_packet },
        }
    }

    pub fn new_mmio_packet(key: u64, mmio_packet: MmioPacket) -> Self {
        Self {
            kind: RvmExitPacketKind::GuestMmio,
            key,
            inner: RvmExitPacketInnner { mmio: mmio_packet },
        }
    }
}

impl Debug for RvmExitPacket {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let mut out = f.debug_struct("RvmExitPacket");
        out.field("kind", &self.kind).field("key", &self.key);
        unsafe {
            match self.kind {
                RvmExitPacketKind::GuestBell => out.field("inner", &self.inner.bell),
                RvmExitPacketKind::GuestIo => out.field("inner", &self.inner.io),
                RvmExitPacketKind::GuestMmio => out.field("inner", &self.inner.mmio),
                _ => out.field("inner", &"Unknown"),
            };
        }
        out.finish()
    }
}
