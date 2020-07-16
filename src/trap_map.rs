//! Some structures to manage traps caused by MMIO/PIO.

use alloc::collections::{btree_map::Entry, BTreeMap};
use alloc::sync::Arc;
use core::convert::TryFrom;

use crate::packet::RvmExitPacket;
use crate::{RvmError, RvmResult};

#[repr(u32)]
#[allow(dead_code)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TrapKind {
    /// Asynchronous trap caused by MMIO.
    GuestTrapBell = 0,
    /// Synchronous traps caused by MMIO.
    GuestTrapMem = 1,
    /// Synchronous traps caused by I/O instructions.
    GuestTrapIo = 2,
    /// Invalid
    _Invalid,
}

impl TryFrom<u32> for TrapKind {
    type Error = RvmError;

    fn try_from(value: u32) -> RvmResult<Self> {
        match value {
            0 => Ok(TrapKind::GuestTrapBell),
            1 => Ok(TrapKind::GuestTrapMem),
            2 => Ok(TrapKind::GuestTrapIo),
            _ => Err(RvmError::InvalidParam),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Trap {
    pub kind: TrapKind,
    pub addr: usize,
    pub size: usize,
    pub key: u64,
    pub port: Option<Arc<dyn RvmPort>>,
}

impl Trap {
    fn contains(&self, addr: usize) -> bool {
        self.addr <= addr && addr < self.addr + self.size
    }
}

#[derive(Debug, Default)]
pub struct TrapMap {
    #[cfg(target_arch = "x86_64")]
    io_traps: BTreeMap<usize, Trap>,
    mem_traps: BTreeMap<usize, Trap>,
}

impl TrapMap {
    pub fn find(&self, kind: TrapKind, addr: usize) -> Option<Trap> {
        let traps = match kind {
            #[cfg(target_arch = "x86_64")]
            TrapKind::GuestTrapIo => &self.io_traps,
            TrapKind::GuestTrapMem | TrapKind::GuestTrapBell => &self.mem_traps,
            _ => return None,
        };
        if let Some((_, trap)) = traps.range(..=addr).last() {
            if trap.contains(addr) {
                return Some(trap.clone());
            }
        }
        None
    }

    pub fn push(
        &mut self,
        kind: TrapKind,
        addr: usize,
        size: usize,
        port: Option<Arc<dyn RvmPort>>,
        key: u64,
    ) -> RvmResult {
        let traps = match kind {
            #[cfg(target_arch = "x86_64")]
            TrapKind::GuestTrapIo => &mut self.io_traps,
            TrapKind::GuestTrapMem | TrapKind::GuestTrapBell => &mut self.mem_traps,
            _ => return Err(RvmError::InvalidParam),
        };
        let trap = Trap {
            kind,
            addr,
            size,
            key,
            port,
        };
        let entry = traps.entry(addr);
        if let Entry::Vacant(e) = entry {
            e.insert(trap);
            Ok(())
        } else {
            Err(RvmError::InvalidParam)
        }
    }
}

/// Used for sending asynchronous message
pub trait RvmPort: core::fmt::Debug + Send + Sync {
    fn send(&self, packet: RvmExitPacket) -> RvmResult;
}
