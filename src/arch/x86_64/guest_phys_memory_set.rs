//! Guest physical memory management structures
//! TODO: Architecture independent

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::RwLock;

use rcore_memory::memory_set::handler::{FrameAllocator, MemoryHandler};
use rcore_memory::memory_set::MemoryAttr;
use rcore_memory::paging::PageTable;
use rcore_memory::{Page, PAGE_SIZE};

use super::epage_table::EPageTable;
use crate::memory::GlobalFrameAlloc;
use crate::rvm::{RvmError, RvmResult};

pub type GuestPhysAddr = usize;
pub type HostPhysAddr = usize;
pub type HostVirtAddr = usize;

#[derive(Debug)]
struct GuestPhysicalMemoryArea {
    start_paddr: GuestPhysAddr,
    end_paddr: GuestPhysAddr,
}

impl GuestPhysicalMemoryArea {
    /// Test whether a guest physical address is in the memory area
    fn contains(&self, guest_paddr: GuestPhysAddr) -> bool {
        self.start_paddr <= guest_paddr && guest_paddr < self.end_paddr
    }

    /// Test whether this area is (page) overlap with area [`start_addr`, `end_addr`)
    fn is_overlap_with(&self, start_paddr: GuestPhysAddr, end_paddr: GuestPhysAddr) -> bool {
        let p0 = Page::of_addr(self.start_paddr);
        let p1 = Page::of_addr(self.end_paddr - 1) + 1;
        let p2 = Page::of_addr(start_paddr);
        let p3 = Page::of_addr(end_paddr - 1) + 1;
        !(p1 <= p2 || p0 >= p3)
    }

    /// Map all pages in the area to page table `pt` to 0 for delay map
    fn map(&self, pt: &mut EPageTable<GlobalFrameAlloc>) {
        for page in Page::range_of(self.start_paddr, self.end_paddr) {
            let mut entry = pt.map(page.start_address(), 0);
            entry.set_present(false);
        }
    }

    /// Unmap all pages in the area from page table `pt`
    fn _unmap(&self, _pt: &mut EPageTable<GlobalFrameAlloc>) {
        // TODO
    }

    /// Do real mapping when an EPT violation occurs
    fn handle_page_fault(
        &self,
        pt: &mut EPageTable<GlobalFrameAlloc>,
        guest_paddr: GuestPhysAddr,
    ) -> bool {
        let mut entry = pt.get_entry(guest_paddr);
        if entry.is_present() {
            return false;
        }
        let frame = GlobalFrameAlloc.alloc().expect("failed to alloc frame");
        entry.set_physical_address(frame);
        entry.set_present(true);
        true
        // From Volume 3, Section 28.3.3.4: Software may use the INVEPT instruction
        // after modifying a present EPT paging-structure entry (see Section 28.2.2)
        // to change any of the privilege bits 2:0 from 0 to 1. Failure to do so may
        // cause an EPT violation that would not otherwise occur. Because an EPT
        // violation invalidates any mappings that would be used by the access that
        // caused the EPT violation (see Section 28.3.3.1), an EPT violation will not
        // recur if the original access is performed again, even if the INVEPT
        // instruction is not executed.
    }
}

#[derive(Debug)]
pub struct GuestPhysicalMemorySet {
    areas: Vec<GuestPhysicalMemoryArea>,
    rvm_page_table: EPageTable<GlobalFrameAlloc>,
}

impl GuestPhysicalMemorySet {
    pub fn new() -> Self {
        Self {
            areas: Vec::new(),
            rvm_page_table: EPageTable::new(GlobalFrameAlloc),
        }
    }

    /// Test if [`start_addr`, `end_addr`) is a free area
    fn test_free_area(&self, start_addr: usize, end_addr: usize) -> bool {
        self.areas
            .iter()
            .find(|area| area.is_overlap_with(start_addr, end_addr))
            .is_none()
    }

    /// Add an area to this set
    pub fn push(&mut self, start_paddr: GuestPhysAddr, size: usize) -> RvmResult<()> {
        let start_paddr = start_paddr & !(PAGE_SIZE - 1);
        let end_paddr = (start_paddr + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if start_paddr >= end_paddr {
            warn!("[RVM] invalid guest physical memory area");
            return Err(RvmError::InvalidParam);
        }
        if !self.test_free_area(start_paddr, end_paddr) {
            warn!("[RVM] guest physical memory area overlap");
            return Err(RvmError::InvalidParam);
        }
        let area = GuestPhysicalMemoryArea {
            start_paddr,
            end_paddr,
        };
        area.map(&mut self.rvm_page_table);
        // keep order by start address
        let idx = self
            .areas
            .iter()
            .enumerate()
            .find(|(_, other)| start_paddr < other.start_paddr)
            .map(|(i, _)| i)
            .unwrap_or(self.areas.len());
        self.areas.insert(idx, area);
        Ok(())
    }

    /// Get the token of the associated page table
    pub fn token(&self) -> usize {
        self.rvm_page_table.eptp()
    }

    /// Clear and unmap all areas
    fn clear(&mut self) {
        // TODO
        println!("[RVM] clear {:#x?}", self);
        self.areas.clear();
    }

    /// Called from the EPT violation handler
    pub fn handle_page_fault(&mut self, guest_paddr: GuestPhysAddr) -> bool {
        debug!("[RVM] handle EPT page fault @ {:#x}", guest_paddr);
        if let Some(area) = self.areas.iter().find(|area| area.contains(guest_paddr)) {
            area.handle_page_fault(&mut self.rvm_page_table, guest_paddr);
            true
        } else {
            false
        }
    }

    pub fn fetch_data(&mut self, guest_paddr: GuestPhysAddr, len: usize) -> Vec<u8> {
        assert!((guest_paddr & (PAGE_SIZE - 1)) + len <= PAGE_SIZE);
        let mut buf = vec![0; len];
        let mut entry = self.rvm_page_table.get_entry(guest_paddr);
        if !entry.is_present() {
            assert!(self.handle_page_fault(guest_paddr));
            entry = self.rvm_page_table.get_entry(guest_paddr);
        }
        let host_paddr = entry.get_physical_address() + (guest_paddr & (PAGE_SIZE - 1));
        let host_vaddr = crate::memory::phys_to_virt(host_paddr);
        unsafe { buf.copy_from_slice(core::slice::from_raw_parts(host_vaddr as *const u8, len)) }
        buf
    }

    pub fn write_data(&mut self, guest_paddr: GuestPhysAddr, data: &[u8]) {
        assert!((guest_paddr & (PAGE_SIZE - 1)) + data.len() <= PAGE_SIZE);
        let mut entry = self.rvm_page_table.get_entry(guest_paddr);
        if !entry.is_present() {
            assert!(self.handle_page_fault(guest_paddr));
            entry = self.rvm_page_table.get_entry(guest_paddr);
        }
        let host_paddr = entry.get_physical_address() + (guest_paddr & (PAGE_SIZE - 1));
        let host_vaddr = crate::memory::phys_to_virt(host_paddr);
        let buf = unsafe { core::slice::from_raw_parts_mut(host_vaddr as *mut u8, data.len()) };
        for i in 0..data.len() {
            buf[i] = data[i];
        }
    }
}

impl Drop for GuestPhysicalMemorySet {
    fn drop(&mut self) {
        self.clear();
    }
}

/// used for mapping vmm's virtual memory to guest os's physical memory
#[derive(Debug, Clone)]
pub struct RvmPageTableHandlerDelay<T: FrameAllocator> {
    guest_start_paddr: GuestPhysAddr,
    host_start_vaddr: HostVirtAddr,
    gpm: Arc<RwLock<GuestPhysicalMemorySet>>,
    allocator: T,
}

impl<T: FrameAllocator> RvmPageTableHandlerDelay<T> {
    pub fn new(
        guest_start_paddr: GuestPhysAddr,
        host_start_vaddr: HostVirtAddr,
        gpm: Arc<RwLock<GuestPhysicalMemorySet>>,
        allocator: T,
    ) -> Self {
        Self {
            guest_start_paddr,
            host_start_vaddr,
            gpm,
            allocator,
        }
    }
}

impl<T: FrameAllocator> MemoryHandler for RvmPageTableHandlerDelay<T> {
    fn box_clone(&self) -> Box<dyn MemoryHandler> {
        Box::new(self.clone())
    }

    fn map(&self, pt: &mut dyn PageTable, addr: HostVirtAddr, attr: &MemoryAttr) {
        let entry = pt.map(addr, 0);
        entry.set_present(false);
        attr.apply(entry);
    }

    fn unmap(&self, pt: &mut dyn PageTable, addr: HostVirtAddr) {
        let entry = pt.get_entry(addr).expect("failed to get entry");
        // PageTable::unmap requires page to be present
        entry.set_present(true);
        pt.unmap(addr);
    }

    fn clone_map(
        &self,
        pt: &mut dyn PageTable,
        src_pt: &mut dyn PageTable,
        addr: HostVirtAddr,
        attr: &MemoryAttr,
    ) {
        let entry = src_pt.get_entry(addr).expect("failed to get entry");
        if entry.present() {
            // eager map and copy data
            let data = src_pt.get_page_slice_mut(addr);
            let target = self.allocator.alloc().expect("failed to alloc frame");
            let entry = pt.map(addr, target);
            attr.apply(entry);
            pt.get_page_slice_mut(addr).copy_from_slice(data);
        } else {
            // delay map
            self.map(pt, addr, attr);
        }
    }

    fn handle_page_fault(&self, pt: &mut dyn PageTable, addr: HostVirtAddr) -> bool {
        let entry = pt.get_entry(addr).expect("failed to get entry");
        if entry.present() {
            // not a delay case
            return false;
        }

        let guest_paddr = addr - self.host_start_vaddr + self.guest_start_paddr;
        let gpm = self.gpm.write();
        let mut rvm_pt_entry = gpm.rvm_page_table.get_entry(guest_paddr);
        let frame = if rvm_pt_entry.is_present() {
            rvm_pt_entry.get_physical_address()
        } else {
            self.allocator.alloc().expect("failed to alloc frame")
        };
        rvm_pt_entry.set_present(true);
        rvm_pt_entry.set_physical_address(frame);
        entry.set_target(frame);
        entry.set_present(true);
        entry.update();
        true
    }
}
