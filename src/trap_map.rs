//! Some structures to manage traps caused by MMIO/PIO.

use alloc::collections::BTreeMap;
use core::convert::TryFrom;

use crate::rvm::{RvmError, RvmResult};

#[repr(u32)]
#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub enum TrapKind {
    Unknown,
    Mmio = 1,
    Io = 2,
}

impl TryFrom<u32> for TrapKind {
    type Error = RvmError;

    fn try_from(value: u32) -> RvmResult<Self> {
        match value {
            1 => Ok(TrapKind::Mmio),
            2 => Ok(TrapKind::Io),
            _ => Err(RvmError::InvalidParam),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct Trap {
    pub kind: TrapKind,
    pub addr: usize,
    pub size: usize,
    pub key: u64,
}

impl Trap {
    fn contains(&self, addr: usize) -> bool {
        self.addr <= addr && addr < self.addr + self.size
    }
}

#[derive(Debug)]
pub struct TrapMap {
    #[cfg(target_arch = "x86_64")]
    io_traps: BTreeMap<usize, Trap>,
    mem_traps: BTreeMap<usize, Trap>,
}

impl TrapMap {
    pub fn new() -> Self {
        Self {
            #[cfg(target_arch = "x86_64")]
            io_traps: BTreeMap::new(),
            mem_traps: BTreeMap::new(),
        }
    }

    pub fn find(&self, kind: TrapKind, addr: usize) -> Option<Trap> {
        let traps = match kind {
            #[cfg(target_arch = "x86_64")]
            TrapKind::Io => &self.io_traps,
            TrapKind::Mmio => &self.mem_traps,
            _ => return None,
        };
        if let Some((_, trap)) = traps.range(..=addr).last() {
            if trap.contains(addr) {
                return Some(*trap);
            }
        }
        None
    }

    pub fn push(&mut self, kind: TrapKind, addr: usize, size: usize, key: u64) -> RvmResult<()> {
        let traps = match kind {
            #[cfg(target_arch = "x86_64")]
            TrapKind::Io => &mut self.io_traps,
            TrapKind::Mmio => &mut self.mem_traps,
            _ => return Err(RvmError::InvalidParam),
        };
        let trap = Trap {
            kind,
            addr,
            size,
            key,
        };
        if traps.contains_key(&addr) {
            Err(RvmError::InvalidParam)
        } else {
            traps.insert(addr, trap);
            Ok(())
        }
    }
}
