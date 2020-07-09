//! The guest within the hypervisor.

use alloc::sync::Arc;
use spin::RwLock;

use super::structs::VMM_STATE;
use crate::memory::{GuestPhysAddr, GuestPhysMemorySetTrait, HostPhysAddr};
use crate::trap_map::{TrapKind, TrapMap};
use crate::PAGE_SIZE;
use crate::{RvmError, RvmResult};

/// Represents a guest within the hypervisor.
#[derive(Debug)]
pub struct Guest {
    pub gpm: Arc<RwLock<dyn GuestPhysMemorySetTrait>>,
    pub traps: RwLock<TrapMap>,
}

impl Guest {
    /// Create a new Guest.
    pub fn new(gpm: impl GuestPhysMemorySetTrait + 'static) -> RvmResult<Arc<Self>> {
        VMM_STATE.lock().alloc()?;
        Ok(Arc::new(Self {
            gpm: Arc::new(RwLock::new(gpm)),
            traps: RwLock::new(TrapMap::default()),
        }))
    }

    /// Get the page table base address.
    pub fn rvm_page_table_phys(&self) -> usize {
        self.gpm.read().table_phys()
    }

    pub fn add_memory_region(
        &self,
        gpaddr: GuestPhysAddr,
        size: usize,
        hpaddr: Option<HostPhysAddr>,
    ) -> RvmResult {
        self.gpm.write().add_map(gpaddr, size, hpaddr)
    }

    pub fn set_trap(&self, kind: TrapKind, addr: usize, size: usize, key: u64) -> RvmResult {
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
