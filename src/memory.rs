use alloc::vec::Vec;
use bitflags::bitflags;

use crate::ffi::alloc_frame;
use crate::{ArchRvmPageTable, RvmError, RvmResult};

pub const PAGE_SIZE: usize = 0x1000;

pub type GuestPhysAddr = usize;
pub type HostPhysAddr = usize;
pub type HostVirtAddr = usize;

bitflags! {
    pub struct RvmPageTableFlags: usize {
        // TODO: cache policy
        const READ      = 1 << 2;
        const WRITE     = 1 << 3;
        const EXECUTE   = 1 << 4;
    }
}

impl Default for RvmPageTableFlags {
    fn default() -> Self {
        Self::READ | Self::WRITE | Self::EXECUTE
    }
}

pub trait RvmPageTable {
    /// Map a guest physical frame starts from `gpaddr` to the host physical
    /// frame starts from of `hpaddr` with `flags`.
    fn map(
        &mut self,
        gpaddr: GuestPhysAddr,
        hpaddr: HostPhysAddr,
        flags: RvmPageTableFlags,
    ) -> RvmResult;

    /// Unmap the guest physical frame `hpaddr`.
    fn unmap(&mut self, gpaddr: GuestPhysAddr) -> RvmResult;

    /// Change the `flags` of the guest physical frame `gpaddr`.
    fn protect(&mut self, gpaddr: GuestPhysAddr, flags: RvmPageTableFlags) -> RvmResult;

    /// Query the host physical address which the guest physical frame of
    /// `gpaddr` maps to.
    fn query(&mut self, gpaddr: GuestPhysAddr) -> RvmResult<HostPhysAddr>;

    /// Page table base address.
    fn table_phys(&self) -> HostPhysAddr;
}

pub trait GuestPhysMemorySetTrait: core::fmt::Debug {
    /// Add a contiguous guest physical memory region and create mapping,
    /// with the target host physical address `hpaddr` (optional).
    fn add_map(
        &mut self,
        gpaddr: GuestPhysAddr,
        size: usize,
        hpaddr: Option<HostPhysAddr>,
    ) -> RvmResult;

    /// Called when accessed a non-mapped guest physical adderss `gpaddr`.
    fn handle_page_fault(&mut self, gpaddr: GuestPhysAddr) -> RvmResult;

    /// Page table base address.
    fn table_phys(&self) -> HostPhysAddr;
}

#[derive(Debug)]
struct GuestPhysicalMemoryRegion {
    start_paddr: GuestPhysAddr,
    end_paddr: GuestPhysAddr,
}

impl GuestPhysicalMemoryRegion {
    /// Test whether a guest physical address is in the memory region
    fn contains(&self, guest_paddr: GuestPhysAddr) -> bool {
        self.start_paddr <= guest_paddr && guest_paddr < self.end_paddr
    }

    /// Test whether this region is (page) overlap with region [`start_addr`, `end_addr`)
    fn is_overlap_with(&self, start_paddr: GuestPhysAddr, end_paddr: GuestPhysAddr) -> bool {
        let p0 = self.start_paddr / PAGE_SIZE;
        let p1 = (self.end_paddr - 1) / PAGE_SIZE + 1;
        let p2 = start_paddr / PAGE_SIZE;
        let p3 = (end_paddr - 1) / PAGE_SIZE + 1;
        !(p1 <= p2 || p0 >= p3)
    }

    /// Map all pages in the region to page table `pt` to 0 for delay map
    fn map(&self, hpaddr: Option<HostPhysAddr>, pt: &mut impl RvmPageTable) {
        for offset in (0..self.end_paddr - self.start_paddr).step_by(PAGE_SIZE) {
            if let Some(hpaddr) = hpaddr {
                pt.map(
                    self.start_paddr + offset,
                    hpaddr + offset,
                    RvmPageTableFlags::default(),
                )
                .unwrap();
            } else {
                pt.map(self.start_paddr + offset, 0, RvmPageTableFlags::empty())
                    .unwrap();
            }
        }
    }

    /// Unmap all pages in the region from page table `pt`
    fn unmap(&self, pt: &mut impl RvmPageTable) {
        for offset in (0..self.end_paddr - self.start_paddr).step_by(PAGE_SIZE) {
            pt.unmap(self.start_paddr + offset).ok();
        }
    }

    /// Do real mapping when an EPT violation occurs
    fn handle_page_fault(&self, pt: &mut impl RvmPageTable, guest_paddr: GuestPhysAddr) -> bool {
        if let Ok(target) = pt.query(guest_paddr) {
            if target != 0 {
                return false;
            }
        }
        let frame = alloc_frame().expect("failed to alloc frame");
        pt.map(guest_paddr, frame, RvmPageTableFlags::default())
            .unwrap();
        // TODO: flush TLB?
        true
    }
}

/// A example implemation if guest physical memory set using delay-mapping, all
/// mappings was created when a VM-exit caused by page fault occurs (e.g. EPT
/// violation in Intel VMX).
#[derive(Debug)]
pub struct DefaultGuestPhysMemorySet {
    regions: Vec<GuestPhysicalMemoryRegion>,
    rvm_page_table: ArchRvmPageTable,
}

impl DefaultGuestPhysMemorySet {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            rvm_page_table: ArchRvmPageTable::new(),
        }
    }

    /// Test if [`start_paddr`, `end_paddr`) is a free region.
    fn test_free_region(&self, start_paddr: GuestPhysAddr, end_paddr: GuestPhysAddr) -> bool {
        self.regions
            .iter()
            .find(|region| region.is_overlap_with(start_paddr, end_paddr))
            .is_none()
    }

    /// Clear and unmap all regions.
    fn clear(&mut self) {
        debug!("[RVM] Guest memory set free {:#x?}", self);
        for region in self.regions.iter() {
            region.unmap(&mut self.rvm_page_table);
        }
        self.regions.clear();
    }
}

impl GuestPhysMemorySetTrait for DefaultGuestPhysMemorySet {
    fn add_map(
        &mut self,
        gpaddr: GuestPhysAddr,
        size: usize,
        hpaddr: Option<HostPhysAddr>,
    ) -> RvmResult {
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
        let region = GuestPhysicalMemoryRegion {
            start_paddr,
            end_paddr,
        };
        region.map(hpaddr, &mut self.rvm_page_table);
        // keep order by start address
        let idx = self
            .regions
            .iter()
            .enumerate()
            .find(|(_, other)| start_paddr < other.start_paddr)
            .map(|(i, _)| i)
            .unwrap_or(self.regions.len());
        self.regions.insert(idx, region);
        Ok(())
    }

    fn handle_page_fault(&mut self, gpaddr: GuestPhysAddr) -> RvmResult {
        debug!("[RVM] handle RVM page fault @ {:#x}", gpaddr);
        if let Some(region) = self.regions.iter().find(|region| region.contains(gpaddr)) {
            region.handle_page_fault(&mut self.rvm_page_table, gpaddr);
            Ok(())
        } else {
            Err(RvmError::NotFound)
        }
    }

    fn table_phys(&self) -> HostPhysAddr {
        self.rvm_page_table.table_phys()
    }
}

impl Drop for DefaultGuestPhysMemorySet {
    fn drop(&mut self) {
        self.clear();
    }
}
