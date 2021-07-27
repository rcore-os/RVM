use alloc::{sync::Arc, vec::Vec};
use spin::Mutex;

use crate::ffi::{alloc_frame, phys_to_virt};
use crate::memory::{GuestPhysAddr, HostPhysAddr, HostVirtAddr, PAGE_SIZE};
use crate::memory::{GuestPhysMemorySetTrait, IntoRvmPageTableFlags, RvmPageTable};
use crate::{ArchRvmPageTable, RvmError, RvmResult};

#[derive(Debug, Clone, Copy)]
pub struct GuestMemoryAttr {
    // TODO: cache policy
    read: bool,
    write: bool,
    execute: bool,
}

impl GuestMemoryAttr {
    fn empty() -> Self {
        Self {
            read: false,
            write: false,
            execute: false,
        }
    }
}

impl Default for GuestMemoryAttr {
    fn default() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
        }
    }
}

impl IntoRvmPageTableFlags for GuestMemoryAttr {
    fn is_read(&self) -> bool {
        self.read
    }
    fn is_write(&self) -> bool {
        self.write
    }
    fn is_execute(&self) -> bool {
        self.execute
    }
}

#[derive(Debug)]
pub struct GuestPhysMemoryRegion {
    start_paddr: GuestPhysAddr,
    end_paddr: GuestPhysAddr,
    attr: GuestMemoryAttr,
}

impl GuestPhysMemoryRegion {
    /// Test whether a guest physical address is in the memory region
    fn contains(&self, guest_paddr: GuestPhysAddr) -> bool {
        self.start_paddr <= guest_paddr && guest_paddr < self.end_paddr
    }

    /// Test whether this region is (page) overlap with region [`start_paddr`, `end_paddr`)
    fn is_overlap_with(&self, start_paddr: GuestPhysAddr, end_paddr: GuestPhysAddr) -> bool {
        let p0 = self.start_paddr / PAGE_SIZE;
        let p1 = (self.end_paddr - 1) / PAGE_SIZE + 1;
        let p2 = start_paddr / PAGE_SIZE;
        let p3 = (end_paddr - 1) / PAGE_SIZE + 1;
        !(p1 <= p2 || p0 >= p3)
    }

    /// Map all pages in the region to page table `pt` to 0 for delay map
    fn map(&self, hpaddr: Option<HostPhysAddr>, pt: &Mutex<impl RvmPageTable>) {
        let mut pt = pt.lock();
        for offset in (0..self.end_paddr - self.start_paddr).step_by(PAGE_SIZE) {
            if let Some(hpaddr) = hpaddr {
                pt.map(self.start_paddr + offset, hpaddr + offset, self.attr)
                    .unwrap();
            } else {
                pt.map(self.start_paddr + offset, 0, GuestMemoryAttr::empty())
                    .unwrap();
            }
        }
    }

    /// Unmap all pages in the region from page table `pt`
    fn unmap(&self, pt: &Mutex<impl RvmPageTable>) {
        let mut pt = pt.lock();
        for offset in (0..self.end_paddr - self.start_paddr).step_by(PAGE_SIZE) {
            pt.unmap(self.start_paddr + offset).ok();
        }
    }

    /// Do real mapping when an EPT violation occurs
    fn handle_page_fault(&self, gpaddr: GuestPhysAddr, pt: &Mutex<impl RvmPageTable>) -> bool {
        let mut pt = pt.lock();
        if let Ok(target) = pt.query(gpaddr) {
            if target != 0 {
                return false;
            }
        }
        let frame = alloc_frame().expect("failed to alloc frame");
        pt.map(gpaddr, frame, self.attr).unwrap();
        // TODO: flush TLB?
        true
    }
}

/// A example implemation if guest physical memory set using delay-mapping, all
/// mappings was created when a VM-exit caused by page fault occurs (e.g. EPT
/// violation in Intel VMX).
#[derive(Debug)]
pub struct DefaultGuestPhysMemorySet {
    pub regions: Mutex<Vec<GuestPhysMemoryRegion>>,
    pub rvm_page_table: Mutex<ArchRvmPageTable>,
    pub table_phys: HostPhysAddr,
}

impl DefaultGuestPhysMemorySet {
    pub fn new() -> Arc<Self> {
        let pt = ArchRvmPageTable::new();
        Arc::new(Self {
            regions: Mutex::new(Vec::new()),
            table_phys: pt.table_phys(),
            rvm_page_table: Mutex::new(pt),
        })
    }

    fn find_region<F, T>(&self, gpaddr: GuestPhysAddr, op: F) -> RvmResult<T>
    where
        F: FnOnce(&GuestPhysMemoryRegion) -> RvmResult<T>,
    {
        if let Some(region) = self
            .regions
            .lock()
            .iter()
            .find(|region| region.contains(gpaddr))
        {
            op(region)
        } else {
            Err(RvmError::NotFound)
        }
    }

    /// Test if [`start_paddr`, `end_paddr`) is a free region.
    fn test_free_region(&self, start_paddr: GuestPhysAddr, end_paddr: GuestPhysAddr) -> bool {
        self.regions
            .lock()
            .iter()
            .any(|region| region.is_overlap_with(start_paddr, end_paddr))
    }

    /// Clear and unmap all regions.
    fn clear(&self) {
        debug!("[RVM] Guest memory set free {:#x?}", self);
        let mut regions = self.regions.lock();
        for region in regions.iter() {
            region.unmap(&self.rvm_page_table);
        }
        regions.clear();
    }

    fn query_range(&self, gpaddr: GuestPhysAddr, size: usize) -> RvmResult<HostVirtAddr> {
        if size > PAGE_SIZE {
            return Err(RvmError::OutOfRange);
        }
        let page_off = gpaddr & (PAGE_SIZE - 1);
        if (page_off + size) > PAGE_SIZE {
            return Err(RvmError::NotSupported);
        }
        self.find_region(gpaddr, |region: &GuestPhysMemoryRegion| {
            if gpaddr + size > region.end_paddr {
                return Err(RvmError::OutOfRange);
            }
            let hpaddr = self.rvm_page_table.lock().query(gpaddr)? + page_off;
            let hvaddr = phys_to_virt(hpaddr);
            Ok(hvaddr)
        })
    }
}

impl GuestPhysMemorySetTrait for DefaultGuestPhysMemorySet {
    fn size(&self) -> u64 {
        1 << 32
    }

    fn map(&self, gpaddr: GuestPhysAddr, size: usize, hpaddr: Option<HostPhysAddr>) -> RvmResult {
        let start_paddr = gpaddr & !(PAGE_SIZE - 1);
        let end_paddr = (start_paddr + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if start_paddr >= end_paddr {
            warn!("[RVM] invalid guest physical memory region");
            return Err(RvmError::InvalidParam);
        }
        if !self.test_free_region(start_paddr, end_paddr) {
            warn!("[RVM] guest physical memory region overlap");
            return Err(RvmError::InvalidParam);
        }
        let region = GuestPhysMemoryRegion {
            start_paddr,
            end_paddr,
            attr: GuestMemoryAttr::default(),
        };
        region.map(hpaddr, &self.rvm_page_table);
        // keep order by start address
        let mut regions = self.regions.lock();
        let idx = regions
            .iter()
            .enumerate()
            .find(|(_, other)| start_paddr < other.start_paddr)
            .map(|(i, _)| i)
            .unwrap_or_else(|| regions.len());
        regions.insert(idx, region);
        Ok(())
    }

    fn unmap(&self, gpaddr: GuestPhysAddr, size: usize) -> RvmResult {
        let start_paddr = gpaddr & !(PAGE_SIZE - 1);
        let end_paddr = (start_paddr + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if start_paddr >= end_paddr {
            warn!("[RVM] invalid guest physical memory region");
            return Err(RvmError::InvalidParam);
        }

        if let Some((idx, region)) =
            self.regions.lock().iter().enumerate().find(|(_, region)| {
                region.start_paddr == start_paddr && region.end_paddr == end_paddr
            })
        {
            region.unmap(&self.rvm_page_table);
            self.regions.lock().remove(idx);
            return Ok(());
        }

        if !self.test_free_region(start_paddr, end_paddr) {
            warn!("[RVM] partially unmap physical memory region is not supported");
            return Err(RvmError::NotSupported);
        }

        GuestPhysMemoryRegion {
            start_paddr,
            end_paddr,
            attr: GuestMemoryAttr::default(),
        }
        .unmap(&self.rvm_page_table);
        Ok(())
    }

    fn read_memory(&self, gpaddr: GuestPhysAddr, buf: &mut [u8]) -> RvmResult<usize> {
        let size = buf.len();
        let hvaddr = self.query_range(gpaddr, size)?;
        unsafe { buf.copy_from_slice(core::slice::from_raw_parts(hvaddr as *const u8, size)) }
        Ok(size)
    }

    fn write_memory(&self, gpaddr: GuestPhysAddr, buf: &[u8]) -> RvmResult<usize> {
        let size = buf.len();
        let hvaddr = self.query_range(gpaddr, size)?;
        unsafe { core::slice::from_raw_parts_mut(hvaddr as *mut u8, size).copy_from_slice(buf) }
        Ok(size)
    }

    fn handle_page_fault(&self, gpaddr: GuestPhysAddr) -> RvmResult {
        debug!("[RVM] handle RVM page fault @ {:#x}", gpaddr);
        self.find_region(gpaddr, |region| {
            region.handle_page_fault(gpaddr, &self.rvm_page_table);
            Ok(())
        })
    }

    fn table_phys(&self) -> HostPhysAddr {
        self.table_phys
    }
}

impl Drop for DefaultGuestPhysMemorySet {
    fn drop(&mut self) {
        self.clear();
    }
}
