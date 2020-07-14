//! The guest within the hypervisor.

use alloc::sync::Arc;
use bitmap_allocator::{BitAlloc, BitAlloc256};
use core::fmt;
use spin::Mutex;

use super::structs::VMM_GLOBAL_STATE;
use crate::memory::{GuestPhysAddr, GuestPhysMemorySetTrait, HostPhysAddr};
use crate::trap_map::{TrapKind, TrapMap};
use crate::PAGE_SIZE;
use crate::{RvmError, RvmResult};

pub(crate) struct VpidAllocator<'a> {
    inner: &'a Mutex<BitAlloc256>,
    free_on_drop: bool,
    allocated_vpid: u16,
}

impl<'a> VpidAllocator<'a> {
    pub fn alloc(&mut self) -> RvmResult<u16> {
        if let Some(vpid) = self.inner.lock().alloc() {
            self.free_on_drop = true;
            self.allocated_vpid = vpid as u16;
            Ok(vpid as u16)
        } else {
            self.free_on_drop = false;
            Err(RvmError::NoMemory)
        }
    }

    pub fn free(&self, vpid: u16) -> RvmResult {
        self.inner.lock().dealloc(vpid as usize);
        Ok(())
    }

    pub fn all_done(&mut self) {
        self.free_on_drop = false;
    }
}

impl<'a> Drop for VpidAllocator<'a> {
    fn drop(&mut self) {
        if self.free_on_drop {
            self.free(self.allocated_vpid).unwrap()
        }
    }
}

/// Represents a guest within the hypervisor.
pub struct Guest {
    pub(super) gpm: Arc<dyn GuestPhysMemorySetTrait>,
    pub(super) traps: Mutex<TrapMap>,
    vpid_allocator: Mutex<BitAlloc256>,
}

impl Guest {
    /// Create a new Guest.
    pub fn new(gpm: Arc<dyn GuestPhysMemorySetTrait>) -> RvmResult<Arc<Self>> {
        VMM_GLOBAL_STATE.lock().alloc()?;
        let mut allocator = BitAlloc256::DEFAULT;
        allocator.insert(1..64);
        Ok(Arc::new(Self {
            gpm,
            traps: Mutex::new(TrapMap::default()),
            vpid_allocator: Mutex::new(allocator),
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
        self.gpm.add_map(gpaddr, size, hpaddr)
    }

    pub fn set_trap(&self, kind: TrapKind, addr: usize, size: usize, key: u64) -> RvmResult {
        if size == 0 {
            return Err(RvmError::InvalidParam);
        }
        if addr > usize::MAX - size {
            return Err(RvmError::OutOfRange);
        }
        match kind {
            // TODO: check port
            TrapKind::GuestTrapIo => {
                if cfg!(target_arch = "aarch64") {
                    return Err(RvmError::NotSupported);
                }
                if addr + size > u16::MAX as usize {
                    Err(RvmError::OutOfRange)
                } else {
                    self.traps.lock().push(kind, addr, size, key)
                }
            }
            TrapKind::GuestTrapBell | TrapKind::GuestTrapMem => {
                if addr & (PAGE_SIZE - 1) != 0 || size & (PAGE_SIZE - 1) != 0 {
                    Err(RvmError::InvalidParam)
                } else {
                    self.gpm.remove_map(addr, size)?;
                    self.traps.lock().push(kind, addr, size, key)
                }
            }
            _ => Err(RvmError::InvalidParam),
        }
    }

    pub(crate) fn vpid_allocator(&self) -> VpidAllocator {
        VpidAllocator {
            inner: &self.vpid_allocator,
            free_on_drop: false,
            allocated_vpid: 0,
        }
    }
}

impl fmt::Debug for Guest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut f = f.debug_struct("Guest");
        f.field("gpm", &self.gpm)
            .field("traps", &self.traps)
            .finish()
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        debug!("Guest free: {:#x?}", self);
        VMM_GLOBAL_STATE.lock().free();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct GuestTest {
        vpid_allocator: Mutex<BitAlloc256>,
    }

    impl GuestTest {
        fn new() -> Arc<Self> {
            let mut allocator = BitAlloc256::DEFAULT;
            allocator.insert(1..64);
            Arc::new(Self {
                vpid_allocator: Mutex::new(allocator),
            })
        }

        fn vpid_allocator(&self) -> VpidAllocator {
            VpidAllocator {
                inner: &self.vpid_allocator,
                free_on_drop: false,
                allocated_vpid: 0,
            }
        }
    }

    #[test]
    fn vpid_alloc_basic() {
        let f = || -> RvmResult {
            let guest = GuestTest::new();
            let mut allocator = guest.vpid_allocator();
            assert_eq!(allocator.alloc()?, 1);
            assert_eq!(allocator.alloc()?, 2);
            assert_eq!(allocator.alloc()?, 3);
            allocator.free(2)?;
            assert_eq!(allocator.alloc()?, 2);
            allocator.free(3)?;
            allocator.free(1)?;
            assert_eq!(allocator.alloc()?, 1);
            assert_eq!(allocator.alloc()?, 3);
            Ok(())
        };
        assert!(f().is_ok());
    }

    #[test]
    fn vpid_alloc_many() {
        let f = || -> RvmResult {
            let guest = GuestTest::new();
            let mut allocator = guest.vpid_allocator();
            for i in 0..63 {
                assert_eq!(allocator.alloc()?, i + 1);
            }
            assert_eq!(allocator.alloc().unwrap_err(), RvmError::NoMemory);
            assert_eq!(allocator.alloc().unwrap_err(), RvmError::NoMemory);
            allocator.free(23)?;
            assert_eq!(allocator.alloc()?, 23);
            assert_eq!(allocator.alloc().unwrap_err(), RvmError::NoMemory);
            Ok(())
        };
        assert!(f().is_ok());
    }

    #[test]
    fn vpid_alloc_auto_free1() {
        let f = || -> RvmResult {
            let guest = GuestTest::new();
            {
                let mut allocator = guest.vpid_allocator();
                assert_eq!(allocator.alloc()?, 1);
            }
            {
                let mut allocator = guest.vpid_allocator();
                assert_eq!(allocator.alloc()?, 1);
                allocator.all_done();
            }
            {
                let mut allocator = guest.vpid_allocator();
                assert_eq!(allocator.alloc()?, 2);
            }
            Ok(())
        };
        assert!(f().is_ok());
    }

    #[test]
    fn vpid_alloc_auto_free2() {
        let guest = GuestTest::new();
        let f = |expected| -> RvmResult {
            let mut allocator = guest.vpid_allocator();
            assert_eq!(allocator.alloc()?, expected);
            Err(RvmError::Internal)?;
            allocator.all_done();
            Ok(())
        };
        let g = |expected| -> RvmResult {
            let mut allocator = guest.vpid_allocator();
            assert_eq!(allocator.alloc()?, expected);
            Ok(())?;
            allocator.all_done();
            Ok(())
        };
        assert_eq!(f(1).err(), Some(RvmError::Internal));
        assert_eq!(g(1).err(), None);
        assert_eq!(g(2).err(), None);
        assert_eq!(g(3).err(), None);
        assert_eq!(f(4).err(), Some(RvmError::Internal));
        assert_eq!(f(4).err(), Some(RvmError::Internal));
        assert_eq!(g(4).err(), None);
        assert_eq!(g(5).err(), None);
    }
}
