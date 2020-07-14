//! Extended Page-Table

use bit_field::BitField;
use bitflags::bitflags;
use core::{convert::TryFrom, fmt};
use numeric_enum_macro::numeric_enum;

use crate::memory::{GuestPhysAddr, HostPhysAddr, IntoRvmPageTableFlags, RvmPageTable, PAGE_SIZE};
use crate::{ffi::*, RvmError, RvmResult};

/// The number of entries in a page table.
const ENTRY_COUNT: usize = 512;

/// Extended page table
#[derive(Debug)]
pub struct EPageTable {
    ept_page_root: HostPhysAddr,
}

impl EPageTable {
    /// Create a new EPageTable.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let mut epage_table = Self { ept_page_root: 0 };
        epage_table.build();
        epage_table
    }

    /// return page entry, will create page table if need
    fn get_entry(
        &self,
        guest_paddr: GuestPhysAddr,
        created_intrm: bool,
    ) -> RvmResult<&mut EPTEntry> {
        let mut page_table = self.ept_page_root;
        let guest_paddr = guest_paddr & !(PAGE_SIZE - 1);
        for level in 0..4 {
            let index = (guest_paddr >> (12 + (3 - level) * 9)) & 0o777;
            let entry = EPTEntry::from(page_table + index * 8);
            if level == 3 {
                return Ok(entry);
            }
            if entry.is_unused() {
                if created_intrm {
                    let new_page = alloc_frame().expect("failed to alloc frame");
                    Self::clear_page(new_page);
                    let intermediate_flags = EPTFlags::READ | EPTFlags::WRITE | EPTFlags::EXECUTE;
                    entry.set_entry(new_page, intermediate_flags, EPTMemoryType::empty());
                } else {
                    return Err(RvmError::NoMemory);
                }
            }
            page_table = entry.addr();
        }
        unreachable!()
    }

    fn clear_page(start_hpaddr: HostPhysAddr) {
        for idx in 0..ENTRY_COUNT {
            EPTEntry::from(start_hpaddr + idx * 8).set_unused();
        }
    }

    fn build(&mut self) {
        assert_eq!(self.ept_page_root, 0);
        self.ept_page_root = alloc_frame().expect("failed to allocate ept_page_root frame");
        Self::clear_page(self.ept_page_root);
        debug!(
            "[RVM] EPageTable: new EPT page root @ {:#x}",
            self.ept_page_root
        );
    }

    fn destroy_dfs(&self, page: HostPhysAddr, level: usize) {
        for idx in 0..ENTRY_COUNT {
            let entry = EPTEntry::from(page + idx * 8);
            if !entry.is_unused() {
                if level == 3 {
                    dealloc_frame(entry.addr());
                } else {
                    self.destroy_dfs(entry.addr(), level + 1);
                }
            }
        }
        dealloc_frame(page);
    }

    fn destroy(&mut self) {
        debug!("[RVM] EPageTable: destroy EPT @ {:#x}", self.ept_page_root);
        self.destroy_dfs(self.ept_page_root, 0);
        self.ept_page_root = 0;
    }
}

impl Drop for EPageTable {
    fn drop(&mut self) {
        self.destroy();
    }
}

impl RvmPageTable for EPageTable {
    fn map(
        &mut self,
        gpaddr: GuestPhysAddr,
        hpaddr: HostPhysAddr,
        flags: impl IntoRvmPageTableFlags,
    ) -> RvmResult {
        trace!(
            "[RVM] EPT map: {:#x?} -> {:#x?}, flags={:?} in {:#x?}",
            gpaddr,
            hpaddr,
            flags,
            self.ept_page_root
        );
        self.get_entry(gpaddr, true)?.set_entry(
            hpaddr,
            EPTFlags::from(flags),
            EPTMemoryType::WriteBack,
        );
        Ok(())
    }

    /// Unmap the guest physical frame `hpaddr`.
    fn unmap(&mut self, gpaddr: GuestPhysAddr) -> RvmResult {
        self.get_entry(gpaddr, false)?.set_unused();
        Ok(())
    }

    /// Change the `flags` of the guest physical frame `gpaddr`.
    fn protect(&mut self, gpaddr: GuestPhysAddr, flags: impl IntoRvmPageTableFlags) -> RvmResult {
        let entry = self.get_entry(gpaddr, false)?;
        entry.set_entry(
            entry.addr(),
            EPTFlags::from(flags),
            EPTMemoryType::WriteBack,
        );
        Ok(())
    }

    /// Query the host physical address which the guest physical frame of
    /// `gpaddr` maps to.
    fn query(&mut self, gpaddr: GuestPhysAddr) -> RvmResult<HostPhysAddr> {
        Ok(self.get_entry(gpaddr, false)?.addr())
    }

    /// Page table base address.
    fn table_phys(&self) -> HostPhysAddr {
        self.ept_page_root
    }
}

struct EPTEntry {
    pub entry: u64,
}

impl EPTEntry {
    pub fn from(hpaddr: HostPhysAddr) -> &'static mut Self {
        let hvaddr = phys_to_virt(hpaddr);
        unsafe { &mut *(hvaddr as *mut Self) }
    }

    /// Returns whether this entry is zero.
    #[inline]
    pub const fn is_unused(&self) -> bool {
        self.entry == 0
    }

    /// Returns the host physical address mapped by this entry, might be zero.
    #[inline]
    pub const fn addr(&self) -> HostPhysAddr {
        (self.entry & 0x0000_ffff_ffff_f000) as usize
    }

    /// Returns the flags of this entry.
    #[inline]
    pub const fn flags(&self) -> EPTFlags {
        EPTFlags::from_bits_truncate(self.entry)
    }

    #[inline]
    /// Returns the memory type field of this entry.
    pub fn memory_type(&self) -> Result<EPTMemoryType, u8> {
        EPTMemoryType::try_from(self.entry.get_bits(3..6) as u8)
    }

    /// Clears all bits.
    #[inline]
    pub fn set_unused(&mut self) {
        self.entry = 0
    }

    #[inline]
    pub fn set_entry(&mut self, hpaddr: HostPhysAddr, flags: EPTFlags, mem_type: EPTMemoryType) {
        let hpaddr = hpaddr & !(PAGE_SIZE - 1);
        self.entry = hpaddr as u64 | flags.bits();
        self.entry.set_bits(3..6, mem_type as u64);
    }
}

impl fmt::Debug for EPTEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut f = f.debug_struct("PageTableEntry");
        f.field("hpaddr", &self.addr());
        f.field("flags", &self.flags());
        f.field("memory_type", &self.memory_type());
        f.finish()
    }
}

bitflags! {
    struct EPTFlags: u64 {
        /// Read access.
        const READ =                1 << 0;
        /// Write access.
        const WRITE =               1 << 1;
        /// execute access.
        const EXECUTE =             1 << 2;
        /// Ignore PAT memory type
        const IGNORE_PAT =          1 << 6;
        /// If bit 6 of EPTP is 1, accessed flag for EPT.
        const ACCESSED =            1 << 8;
        /// If bit 6 of EPTP is 1, dirty flag for EPT;
        const DIRTY =               1 << 9;
        /// Execute access for user-mode linear addresses.
        const EXECUTE_FOR_USER =    1 << 10;
    }
}

impl EPTFlags {
    fn from(flags: impl IntoRvmPageTableFlags) -> Self {
        let mut f = Self::empty();
        if flags.is_read() {
            f |= Self::READ;
        }
        if flags.is_write() {
            f |= Self::WRITE;
        }
        if flags.is_execute() {
            f |= Self::EXECUTE;
        }
        f
    }
}

numeric_enum! {
    #[repr(u8)]
    #[derive(Debug, PartialEq, Clone, Copy)]
    enum EPTMemoryType {
        Uncached = 0,
        WriteCombining = 1,
        WriteThrough = 4,
        WriteProtected = 5,
        WriteBack = 6,
    }
}

impl EPTMemoryType {
    pub fn empty() -> Self {
        Self::try_from(0).unwrap()
    }
}
