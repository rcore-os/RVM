//! The packet forwarded to userspace on VM Exits.

use core::fmt::{Debug, Formatter, Result};

#[repr(u32)]
#[derive(Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum RvmExitPacketKind {
    #[cfg(target_arch = "x86_64")]
    GuestBell = 1,
    #[cfg(target_arch = "x86_64")]
    GuestIo = 2,
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    GuestEcall = 1,
    GuestMmio = 3,
    GuestVcpu = 4,
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    GuestYield = 5,
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

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
#[repr(C)]
#[derive(Debug, Default)]
pub struct EcallPacket {
    pub eid: i32,
    pub fid: i32,
    pub arg0: usize,
    pub arg1: usize,
    pub arg2: usize,
    pub arg3: usize,
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
    pub execute: bool,
    pub data: u64,
    pub dstreg: u8,
    pub extension: bool,
    pub insn: u32,
    pub inst_len: u8,
}

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
#[repr(C)]
#[derive(Debug, Default)]
pub struct YieldPacket {
    pub magic: u64,
}

#[repr(C)]
pub union RvmExitPacketInner {
    #[cfg(target_arch = "x86_64")]
    pub bell: BellPacket,
    #[cfg(target_arch = "x86_64")]
    pub io: IoPacket,
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    pub ecall: EcallPacket,
    pub mmio: MmioPacket,
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    pub yield_pack: YieldPacket,
}

#[repr(C)]
pub struct RvmExitPacket {
    pub kind: RvmExitPacketKind,
    pub key: u64,
    pub inner: RvmExitPacketInner,
}

impl RvmExitPacket {
    #[cfg(target_arch = "x86_64")]
    pub fn new_bell_packet(key: u64, addr: u64) -> Self {
        Self {
            kind: RvmExitPacketKind::GuestBell,
            key,
            inner: RvmExitPacketInner {
                bell: BellPacket { addr },
            },
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn new_io_packet(key: u64, io_packet: IoPacket) -> Self {
        Self {
            kind: RvmExitPacketKind::GuestIo,
            key,
            inner: RvmExitPacketInner { io: io_packet },
        }
    }

    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    pub fn new_ecall_packet(key: u64, ecall_packet: EcallPacket) -> Self {
        Self {
            kind: RvmExitPacketKind::GuestEcall,
            key,
            inner: RvmExitPacketInner {
                ecall: ecall_packet,
            },
        }
    }
    pub fn new_mmio_packet(key: u64, mmio_packet: MmioPacket) -> Self {
        Self {
            kind: RvmExitPacketKind::GuestMmio,
            key,
            inner: RvmExitPacketInner { mmio: mmio_packet },
        }
    }
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    pub fn new_yield_packet(key: u64, yield_packet: YieldPacket) -> Self {
        Self {
            kind: RvmExitPacketKind::GuestYield,
            key,
            inner: RvmExitPacketInner {
                yield_pack: yield_packet,
            },
        }
    }
}

impl Debug for RvmExitPacket {
    fn fmt(&self, f: &mut Formatter) -> Result {
        let mut out = f.debug_struct("RvmExitPacket");
        out.field("kind", &self.kind).field("key", &self.key);
        unsafe {
            match self.kind {
                #[cfg(target_arch = "x86_64")]
                RvmExitPacketKind::GuestBell => out.field("inner", &self.inner.bell),
                #[cfg(target_arch = "x86_64")]
                RvmExitPacketKind::GuestIo => out.field("inner", &self.inner.io),
                #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
                RvmExitPacketKind::GuestEcall => out.field("inner", &self.inner.ecall),
                RvmExitPacketKind::GuestMmio => out.field("inner", &self.inner.mmio),
                #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
                RvmExitPacketKind::GuestYield => out.field("inner", &self.inner.yield_pack),
                _ => out.field("inner", &"Unknown"),
            };
        }
        out.finish()
    }
}
