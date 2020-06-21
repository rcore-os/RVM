//! The guest within the hypervisor.

use alloc::boxed::Box;
use alloc::sync::Arc;
use spin::RwLock;

use rcore_memory::{memory_set::MemoryAttr, PAGE_SIZE};

use super::guest_phys_memory_set::{
    GuestPhysAddr, GuestPhysicalMemorySet, HostVirtAddr, RvmPageTableHandlerDelay,
};
use super::structs::VMM_STATE;
use crate::memory::GlobalFrameAlloc;
use crate::rvm::trap_map::{TrapKind, TrapMap};
use crate::rvm::{RvmError, RvmResult};

/// Represents a guest within the hypervisor.
#[derive(Debug)]
pub struct Guest {
    pub gpm: Arc<RwLock<GuestPhysicalMemorySet>>,
    pub traps: RwLock<TrapMap>,
}

impl Guest {
    pub fn new() -> RvmResult<Box<Self>> {
        VMM_STATE.lock().alloc()?;
        Ok(Box::new(Self {
            gpm: Arc::new(RwLock::new(GuestPhysicalMemorySet::new())),
            traps: RwLock::new(TrapMap::new()),
        }))
    }

    pub fn eptp(&self) -> usize {
        self.gpm.read().token()
    }

    pub fn add_memory_region(
        &self,
        start_paddr: GuestPhysAddr,
        size: usize,
    ) -> RvmResult<HostVirtAddr> {
        self.gpm.write().push(start_paddr, size)?;

        let mut vm = unsafe { crate::process::current_thread().vm.lock() };
        let vaddr = vm.find_free_area(PAGE_SIZE, size);
        let handler =
            RvmPageTableHandlerDelay::new(start_paddr, vaddr, self.gpm.clone(), GlobalFrameAlloc);
        vm.push(
            vaddr,
            vaddr + size,
            MemoryAttr::default().user().writable(),
            handler,
            "rvm_guest_physical",
        );
        Ok(vaddr)
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
        println!("Guest free {:#x?}", self);
        VMM_STATE.lock().free();
    }
}
