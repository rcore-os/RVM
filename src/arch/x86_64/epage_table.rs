// ref: https://github.com/SinaKarvandi/Hypervisor-From-Scratch/blob/master/Part%204%20-%20Address%20Translation%20Using%20Extended%20Page%20Table%20(EPT)/MyHypervisorDriver/MyHypervisorDriver/EPT.h
// TODO: better code style

#![allow(dead_code)]

use super::consts::PAGE_SIZE;
use crate::memory::*;

const MASK_PAGE_ALIGNED: usize = PAGE_SIZE - 1;

/// Extended page table
#[derive(Debug)]
pub struct EPageTable {
    ept_page_root: HostPhysAddr,
}

impl EPageTable {
    /// Create a new EPageTable.
    ///
    /// # Arguments
    ///     * allocator: FrameAllocator<Size4KiB>
    pub fn new() -> Self {
        let mut epage_table = Self { ept_page_root: 0 };
        epage_table.build();
        epage_table
    }

    /// Return EPT value (i.e. the physical address of root extended page table)
    pub fn pointer(&self) -> usize {
        let mut eptp = EPageTablePointer::new();
        eptp.set_dirty_and_access_enabled(true);
        eptp.set_memory_type(6);
        eptp.set_page_walk_length(3);
        eptp.set_epage_table_root(self.ept_page_root);
        return eptp.value();
    }

    /// Map a guest physical page to host physical page.
    pub fn map(&mut self, guest_paddr: GuestPhysAddr, host_paddr: HostPhysAddr) -> EPageEntry {
        let mut entry = self.get_entry(guest_paddr);
        assert!(!entry.is_present());
        entry.set_physical_address(host_paddr);
        entry.set_present(true);
        entry.set_ept_memory_type(6);
        entry
    }

    /// return page entry, will create page table if need
    pub fn get_entry(&self, guest_paddr: GuestPhysAddr) -> EPageEntry {
        let mut page_table = self.ept_page_root;
        for level in 0..4 {
            let index = (guest_paddr >> (12 + (3 - level) * 9)) & 0o777;
            let mut entry = EPageEntry::new(page_table + index * 8);
            if level == 3 {
                return entry;
            }
            if !entry.is_present() {
                let new_page = alloc_frame().expect("failed to alloc frame");
                // clear all entry
                for idx in 0..512 {
                    EPageEntry::new(new_page + idx * 8).zero();
                }
                entry.set_physical_address(new_page);
                entry.set_present(true);
            }
            page_table = entry.get_physical_address();
        }
        unreachable!();
    }

    fn build(&mut self) {
        assert_eq!(self.ept_page_root, 0);
        self.ept_page_root = alloc_frame().expect("failed to allocate ept_page_root frame");
        // clear all entry
        for idx in 0..512 {
            EPageEntry::new(self.ept_page_root + idx * 8).zero();
        }
        info!(
            "[RVM] epage_table: successed alloc ept page root 0x{:x}",
            self.ept_page_root
        );

        info!("[RVM] epage_table: successed build ept");
    }
    fn unbuild_dfs(&self, page: HostPhysAddr, level: usize) {
        for idx in 0..512 {
            let entry = EPageEntry::new(page + idx * 8);
            if entry.is_present() {
                if level == 3 {
                    dealloc_frame(entry.get_physical_address());
                } else {
                    self.unbuild_dfs(entry.get_physical_address(), level + 1);
                }
            }
        }
        dealloc_frame(page);
    }
    fn unbuild(&mut self) {
        self.unbuild_dfs(self.ept_page_root, 0);
        self.ept_page_root = 0;
        info!("[RVM] epage_table: successed unbuild ept");
    }
}

impl Drop for EPageTable {
    fn drop(&mut self) {
        self.unbuild();
    }
}

/*
struct {
    UINT64 Read : 1; // bit 0
    UINT64 Write : 1; // bit 1
    UINT64 Execute : 1; // bit 2
    UINT64 EPTMemoryType : 3; // bit 5:3 (EPT Memory type) (last level entry only)
    UINT64 IgnorePAT : 1; // bit 6 (last level entry only)
    UINT64 Ignored1 : 1; // bit 7
    UINT64 AccessedFlag : 1; // bit 8
    UINT64 DirtyFlag : 1; // bit 9 (last level entry only)
    UINT64 ExecuteForUserMode : 1; // bit 10
    UINT64 Ignored2 : 1; // bit 11
    UINT64 PhysicalAddress : 36; // bit (N-1):12 or Page-Frame-Number
    UINT64 Reserved : 4; // bit 51:N
    UINT64 Ignored3 : 11; // bit 62:52
    UINT64 SuppressVE : 1; // bit 63 (last level entry only)
}Fields;
*/
// TODO: use bitflags
pub struct EPageEntry {
    hpaaddr: HostPhysAddr, // host physical addr
}

impl EPageEntry {
    fn new(hpaaddr: HostPhysAddr) -> Self {
        Self { hpaaddr }
    }
    fn get_value(&self) -> usize {
        let va = phys_to_virt(self.hpaaddr);
        unsafe { *(va as *const usize) }
    }
    fn set_value(&mut self, value: usize) {
        let va = phys_to_virt(self.hpaaddr);
        unsafe {
            *(va as *mut usize) = value;
        };
    }
    fn get_bits(&self, s: usize, t: usize) -> usize {
        assert!(s < t && t <= 64);
        let value = self.get_value();
        (value >> s) & ((1 << (t - s)) - 1)
    }
    fn set_bits(&mut self, s: usize, t: usize, value: usize) {
        assert!(s < t && t <= 64);
        assert!(value < (1 << (t - s)));
        let old_value = self.get_value();
        self.set_value(old_value - (self.get_bits(s, t) << s) + (value << s));
    }

    fn zero(&mut self) {
        self.set_value(0);
    }
    pub fn is_present(&self) -> bool {
        self.get_bits(0, 3) != 0
    }
    pub fn set_present(&mut self, value: bool) {
        if value {
            self.set_bits(0, 3, 0b111)
        } else {
            self.set_bits(0, 3, 0)
        }
    }

    fn get_read(&self) -> bool {
        self.get_bits(0, 1) != 0
    }
    fn set_read(&mut self, value: bool) {
        self.set_bits(0, 1, value as usize)
    }

    fn get_write(&self) -> bool {
        self.get_bits(1, 2) != 0
    }
    fn set_write(&mut self, value: bool) {
        self.set_bits(1, 2, value as usize)
    }

    fn get_execute(&self) -> bool {
        self.get_bits(2, 3) != 0
    }
    fn set_execute(&mut self, value: bool) {
        self.set_bits(2, 3, value as usize)
    }

    fn get_ept_memory_type(&self) -> usize {
        self.get_bits(3, 6)
    }
    fn set_ept_memory_type(&mut self, value: usize) {
        self.set_bits(3, 6, value)
    }

    fn get_accessed(&self) -> bool {
        self.get_bits(8, 9) != 0
    }
    fn set_accessed(&mut self, value: bool) {
        self.set_bits(8, 9, value as usize)
    }

    fn get_dirty(&self) -> bool {
        self.get_bits(9, 10) != 0
    }
    fn set_dirty(&mut self, value: bool) {
        self.set_bits(9, 10, value as usize)
    }

    fn get_execute_for_user_mode(&self) -> bool {
        self.get_bits(10, 11) != 0
    }
    fn set_execute_for_user_mode(&mut self, value: bool) {
        self.set_bits(10, 11, value as usize)
    }

    pub fn get_physical_address(&self) -> HostPhysAddr {
        self.get_bits(12, 48) << 12
    }
    pub fn set_physical_address(&mut self, value: HostPhysAddr) {
        assert_eq!(value & MASK_PAGE_ALIGNED, 0);
        self.set_bits(12, 48, value >> 12);
    }
}

/*
struct {
    UINT64 MemoryType : 3; // bit 2:0 (0 = Uncacheable (UC) - 6 = Write - back(WB))
    UINT64 PageWalkLength : 3; // bit 5:3 (This value is 1 less than the EPT page-walk length)
    UINT64 DirtyAndAceessEnabled : 1; // bit 6  (Setting this control to 1 enables accessed and dirty flags for EPT)
    UINT64 Reserved1 : 5; // bit 11:7
    UINT64 PML4Address : 36;
    UINT64 Reserved2 : 16;
}Fields;
*/
struct EPageTablePointer {
    value: usize,
}

impl EPageTablePointer {
    fn new() -> Self {
        Self { value: 0 }
    }
    fn value(&self) -> usize {
        self.value
    }

    fn get_bits(&self, s: usize, t: usize) -> usize {
        assert!(s < t && t <= 64);
        (self.value >> s) & ((1 << (t - s)) - 1)
    }
    fn set_bits(&mut self, s: usize, t: usize, value: usize) {
        assert!(s < t && t <= 64);
        assert!(value < (1 << (t - s)));
        self.value = self.value - self.get_bits(s, t) + (value << s);
    }

    fn get_memory_type(&self) -> usize {
        self.get_bits(0, 3)
    }
    fn set_memory_type(&mut self, value: usize) {
        self.set_bits(0, 3, value);
    }

    fn get_page_walk_length(&self) -> usize {
        self.get_bits(3, 6)
    }
    fn set_page_walk_length(&mut self, value: usize) {
        self.set_bits(3, 6, value);
    }

    fn get_dirty_and_access_enabled(&self) -> bool {
        self.get_bits(6, 7) != 0
    }
    fn set_dirty_and_access_enabled(&mut self, value: bool) {
        self.set_bits(6, 7, value as usize);
    }

    fn get_epage_table_root(&self) -> usize {
        self.get_bits(12, 48) << 12
    }
    fn set_epage_table_root(&mut self, value: HostPhysAddr) {
        assert_eq!(value & MASK_PAGE_ALIGNED, 0);
        self.set_bits(12, 48, value >> 12);
    }
}
