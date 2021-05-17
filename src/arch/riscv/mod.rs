mod ptx4;

mod decode;
mod pseudoinsn;
mod runvm;
pub mod sbi;
mod traps;
mod vcpu;
pub use runvm::{VMMContext, VMMContextPriv};
pub use vcpu::{InterruptState, Vcpu, VcpuState};

pub type ArchRvmPageTable = ptx4::PageTableSv48X4;
use crate::memory::{GuestPhysAddr, GuestPhysMemorySetTrait, HostPhysAddr};
use crate::trap_map::{RvmPort, TrapKind, TrapMap};
use crate::PAGE_SIZE;
use crate::{RvmError, RvmResult};
use alloc::sync::Arc;
use alloc::vec::Vec;
use riscv::register::*;
use spin::Mutex;
use spin::RwLock;
use traps::*;
pub fn check_hypervisor_feature() -> bool {
    // RISC-V does now allow checking hypervisor feature directly.
    // Instead, throw back the task to OS.
    crate::ffi::riscv_check_hypervisor_extension()
}
use core::sync::atomic::*;
static VMID_ALLOCATOR: AtomicUsize = AtomicUsize::new(1);
static INITIALIZED: AtomicUsize = AtomicUsize::new(0);
pub struct Guest {
    vmid: usize,
    gpm: Arc<dyn GuestPhysMemorySetTrait>,
    traps: Mutex<TrapMap>,
    interrupt_handlers: RwLock<Vec<Arc<InterruptState>>>,
}
impl Guest {
    pub fn get_irq_by_id(&self, cpuid: usize) -> Arc<InterruptState> {
        Arc::clone(self.interrupt_handlers.read().get(cpuid).unwrap())
    }
    fn alloc_cpuid(&self) -> usize {
        let mut irh = self.interrupt_handlers.write();
        let new_id = irh.len();
        irh.push(Arc::new(InterruptState::new()));
        new_id
    }
    pub fn use_pt(&self) {
        let mut val = hgatp::Hgatp::from_bits(0);
        val.set_vmid(self.vmid);
        val.set_ppn(self.rvm_page_table_phys() >> 12);
        val.set_mode(hgatp::HgatpValues::Sv48x4);
        unsafe {
            val.write();
        }
    }
    /// Create a new Guest.
    pub fn new(gpm: Arc<dyn GuestPhysMemorySetTrait>) -> RvmResult<Arc<Self>> {
        if INITIALIZED.swap(1, Ordering::Relaxed) == 0 {
            init_traps();
        }
        Ok(Arc::new(Self {
            vmid: VMID_ALLOCATOR.fetch_add(1, Ordering::Relaxed),
            gpm,
            traps: Mutex::new(TrapMap::default()),
            interrupt_handlers: RwLock::default(),
        }))
    }

    /// Get the page table base address.
    pub(crate) fn rvm_page_table_phys(&self) -> usize {
        self.gpm.table_phys()
    }

    pub fn add_memory_region(
        &self,
        gpaddr: GuestPhysAddr,
        size: usize,
        hpaddr: Option<HostPhysAddr>,
    ) -> RvmResult {
        if gpaddr & (PAGE_SIZE - 1) != 0 || size & (PAGE_SIZE - 1) != 0 {
            return Err(RvmError::InvalidParam);
        }
        if let Some(hpaddr) = hpaddr {
            if hpaddr & (PAGE_SIZE - 1) != 0 {
                return Err(RvmError::InvalidParam);
            }
        }
        self.gpm.map(gpaddr, size, hpaddr)
    }

    pub fn set_trap(
        &self,
        kind: TrapKind,
        addr: usize,
        size: usize,
        port: Option<Arc<dyn RvmPort>>,
        key: u64,
    ) -> RvmResult {
        if size == 0 {
            return Err(RvmError::InvalidParam);
        }
        if addr > usize::MAX - size {
            return Err(RvmError::OutOfRange);
        }
        match kind {
            TrapKind::GuestTrapIo => {
                return Err(RvmError::NotSupported);
            }
            TrapKind::GuestTrapBell => {
                return Err(RvmError::NotSupported);
            }
            TrapKind::GuestTrapMem => {
                if kind == TrapKind::GuestTrapBell && port.is_none() {
                    return Err(RvmError::InvalidParam);
                }
                if kind == TrapKind::GuestTrapMem && port.is_some() {
                    return Err(RvmError::InvalidParam);
                }
                if addr & (PAGE_SIZE - 1) != 0 || size & (PAGE_SIZE - 1) != 0 {
                    Err(RvmError::InvalidParam)
                } else {
                    self.gpm.unmap(addr, size)?;
                    self.traps.lock().push(kind, addr, size, port, key)
                }
            }
            _ => Err(RvmError::InvalidParam),
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct VcpuIo {
    // ?
}
