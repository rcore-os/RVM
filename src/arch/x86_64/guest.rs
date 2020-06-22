//! The guest within the hypervisor.

use alloc::sync::Arc;
use spin::RwLock;

use super::consts::PAGE_SIZE;
use super::epage_table::EPageTable;
use super::structs::VMM_STATE;
use crate::memory::*;
use crate::trap_map::{TrapKind, TrapMap};
use crate::{RvmError, RvmResult};

/// Represents a guest within the hypervisor.
#[derive(Debug)]
pub struct Guest {
    page_table: RwLock<EPageTable>,
    pub traps: RwLock<TrapMap>,
}

impl Guest {
    /// Create a new Guest.
    pub fn new() -> RvmResult<Arc<Self>> {
        VMM_STATE.lock().alloc()?;
        Ok(Arc::new(Self {
            page_table: RwLock::new(EPageTable::new()),
            traps: RwLock::new(TrapMap::new()),
        }))
    }

    /// Get extended page-table pointer.
    pub fn extended_page_table_pointer(&self) -> usize {
        self.page_table.read().pointer()
    }

    pub fn add_memory_region(
        &self,
        gpaddr: GuestPhysAddr,
        hpaddr: HostPhysAddr,
        size: usize,
    ) -> RvmResult {
        assert_eq!(gpaddr % PAGE_SIZE, 0);
        assert_eq!(hpaddr % PAGE_SIZE, 0);
        assert_eq!(size % PAGE_SIZE, 0);
        let mut pt = self.page_table.write();
        for offset in (0..size).step_by(PAGE_SIZE) {
            pt.map(gpaddr + offset, hpaddr + offset);
        }
        Ok(())
    }

    pub fn set_trap(&self, kind: TrapKind, addr: usize, size: usize, key: u64) -> RvmResult<()> {
        match kind {
            TrapKind::Io => {
                if addr + size > u16::MAX as usize {
                    Err(RvmError::InvalidParam)
                } else {
                    self.traps.write().push(kind, addr, size, key)
                }
            }
            TrapKind::Mmio => {
                if addr & (PAGE_SIZE - 1) != 0 || size & (PAGE_SIZE - 1) != 0 {
                    Err(RvmError::InvalidParam)
                } else {
                    self.traps.write().push(kind, addr, size, key)
                }
            }
            _ => Err(RvmError::InvalidParam),
        }
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        info!("Guest free {:#x?}", self);
        VMM_STATE.lock().free();
    }
}
