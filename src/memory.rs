use alloc::vec::Vec;

use crate::{RvmError, RvmResult};

pub const PAGE_SIZE: usize = 0x1000;

pub type GuestPhysAddr = usize;
pub type HostPhysAddr = usize;
pub type HostVirtAddr = usize;

pub trait IntoRvmPageTableFlags: core::fmt::Debug {
    // TODO: cache policy
    fn is_read(&self) -> bool;
    fn is_write(&self) -> bool;
    fn is_execute(&self) -> bool;
}

pub trait RvmPageTable {
    /// Map a guest physical frame starts from `gpaddr` to the host physical
    /// frame starts from of `hpaddr` with `flags`.
    fn map(
        &mut self,
        gpaddr: GuestPhysAddr,
        hpaddr: HostPhysAddr,
        flags: impl IntoRvmPageTableFlags,
    ) -> RvmResult;

    /// Unmap the guest physical frame `hpaddr`.
    fn unmap(&mut self, gpaddr: GuestPhysAddr) -> RvmResult;

    /// Change the `flags` of the guest physical frame `gpaddr`.
    fn protect(&mut self, gpaddr: GuestPhysAddr, flags: impl IntoRvmPageTableFlags) -> RvmResult;

    /// Query the host physical address which the guest physical frame of
    /// `gpaddr` maps to.
    fn query(&mut self, gpaddr: GuestPhysAddr) -> RvmResult<HostPhysAddr>;

    /// Page table base address.
    fn table_phys(&self) -> HostPhysAddr;
}

pub trait GuestPhysMemorySetTrait: core::fmt::Debug + Send + Sync {
    /// Physical address space size.
    fn size(&self) -> u64;

    /// Add a contiguous guest physical memory region and create mapping,
    /// with the target host physical address `hpaddr` (optional).
    fn add_map(
        &self,
        gpaddr: GuestPhysAddr,
        size: usize,
        hpaddr: Option<HostPhysAddr>,
    ) -> RvmResult;

    /// Remove a guest physical memory region, destroy the mapping.
    fn remove_map(&self, gpaddr: GuestPhysAddr, size: usize) -> RvmResult;

    /// Query the host physical address which the guest physical frame of
    /// `gpaddr` maps to.
    fn query(&self, gpaddr: GuestPhysAddr) -> RvmResult<HostPhysAddr>;

    /// Called when accessed a non-mapped guest physical adderss `gpaddr`.
    fn handle_page_fault(&self, gpaddr: GuestPhysAddr) -> RvmResult;

    /// Page table base address.
    fn table_phys(&self) -> HostPhysAddr;
}

impl dyn GuestPhysMemorySetTrait {
    pub fn read_memory(&self, gpaddr: GuestPhysAddr, buf: &mut [u8]) -> RvmResult {
        let size = buf.len();
        if size > PAGE_SIZE {
            return Err(RvmError::OutOfRange);
        }
        let page_off = gpaddr & (PAGE_SIZE - 1);
        if (page_off + size) > PAGE_SIZE {
            return Err(RvmError::NotSupported);
        }

        let hpaddr = self.query(gpaddr)? + page_off;
        let hvaddr = crate::ffi::phys_to_virt(hpaddr);

        unsafe { buf.copy_from_slice(core::slice::from_raw_parts(hvaddr as *const u8, size)) }
        Ok(())
    }

    pub fn read_memory_as_vec(&self, gpaddr: GuestPhysAddr, size: usize) -> RvmResult<Vec<u8>> {
        let mut buf = vec![0; size];
        self.read_memory(gpaddr, buf.as_mut_slice())?;
        Ok(buf)
    }
}
