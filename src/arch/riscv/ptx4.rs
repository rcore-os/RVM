use crate::ffi::*;
use crate::memory::*;
use crate::RvmResult;
use riscv::addr::{FrameWith, PageWith};
use riscv::paging::{Mapper, MapperFlushable, PageTableX64, Rv48PageTableX4};

#[derive(Debug)]
struct OwnedSv48PT {
    root_virt_addr: HostVirtAddr,
    linear_offset: usize,
}

impl OwnedSv48PT {
    pub fn new() -> Self {
        let root_addr = alloc_frame_x4().expect("failed to allocate Sv48x4 root page.");
        assert_eq!(
            root_addr & 0x3fff,
            0,
            "Sv48x4 root page should be 16KiB aligned."
        );
        let root_virt_addr = phys_to_virt(root_addr);
        let linear_offset = root_virt_addr - root_addr;
        let mut ret = OwnedSv48PT {
            root_virt_addr,
            linear_offset,
        };
        ret.root_pt().zero();
        ret
    }
    pub fn phys_addr(&self) -> HostPhysAddr {
        self.root_virt_addr - self.linear_offset
    }
    pub fn root_pt<'a>(&'a mut self) -> &mut PageTableX64 {
        unsafe { &mut *(self.root_virt_addr as *mut _) }
    }
    pub fn to_page_table<'a>(&'a mut self) -> Rv48PageTableX4<'a> {
        let offset = self.linear_offset;
        Rv48PageTableX4::new(self.root_pt(), offset)
    }
}
impl Drop for OwnedSv48PT {
    fn drop(&mut self) {
        dealloc_frame_x4(self.phys_addr());
    }
}

#[derive(Debug)]
pub struct PageTableSv48X4 {
    pt: OwnedSv48PT,
}

use riscv::addr::PhysicalAddress;
use riscv::paging::{FrameAllocatorFor, FrameDeallocatorFor};

pub struct RVMFrameAllocator;
impl<P: PhysicalAddress> FrameAllocatorFor<P> for RVMFrameAllocator {
    fn alloc(&mut self) -> Option<FrameWith<P>> {
        alloc_frame().map(|x| FrameWith::of_ppn(x >> 12))
    }
}
impl<P: PhysicalAddress> FrameDeallocatorFor<P> for RVMFrameAllocator {
    fn dealloc(&mut self, frame: FrameWith<P>) {
        dealloc_frame(frame.start_address().as_usize());
    }
}

impl PageTableSv48X4 {
    pub fn new() -> Self {
        PageTableSv48X4 {
            pt: OwnedSv48PT::new(),
        }
    }
}

use riscv::paging::PageTableFlags;
fn rvm_pt_flags_to_rv_pt_flags(flags: impl IntoRvmPageTableFlags) -> PageTableFlags {
    let mut f = PageTableFlags::VALID | PageTableFlags::USER;
    if flags.is_execute() {
        f |= PageTableFlags::EXECUTABLE;
    }
    if flags.is_read() {
        f |= PageTableFlags::READABLE;
    }
    if flags.is_write() {
        f |= PageTableFlags::WRITABLE;
    }
    f
}
use crate::RvmError;
use riscv::paging::{MapToError, UnmapError};
impl From<MapToError> for RvmError {
    fn from(x: MapToError) -> Self {
        match x {
            MapToError::FrameAllocationFailed => RvmError::NoMemory,
            MapToError::PageAlreadyMapped => RvmError::InvalidParam,
            MapToError::ParentEntryHugePage => RvmError::BadState,
        }
    }
}
impl<P: PhysicalAddress> From<UnmapError<P>> for RvmError {
    fn from(x: UnmapError<P>) -> Self {
        match x {
            UnmapError::PageNotMapped => RvmError::OutOfRange,
            UnmapError::InvalidFrameAddress(_) => RvmError::InvalidParam,
            UnmapError::ParentEntryHugePage => RvmError::BadState,
        }
    }
}

use riscv::paging::FlagUpdateError;
impl From<FlagUpdateError> for RvmError {
    fn from(x: FlagUpdateError) -> Self {
        match x {
            FlagUpdateError::PageNotMapped => RvmError::OutOfRange,
        }
    }
}

impl RvmPageTable for PageTableSv48X4 {
    /// Map a guest physical frame starts from `gpaddr` to the host physical
    /// frame starts from of `hpaddr` with `flags`.
    fn map(
        &mut self,
        gpaddr: GuestPhysAddr,
        hpaddr: HostPhysAddr,
        flags: impl IntoRvmPageTableFlags,
    ) -> RvmResult {
        if hpaddr > 0 {
            info!(
                "gpaddr={:x}, hpaddr={:x}, flags = {:?}",
                gpaddr, hpaddr, flags
            );
            let flusher = self
                .pt
                .to_page_table()
                .map_to(
                    PageWith::of_vpn(gpaddr >> 12),
                    FrameWith::of_ppn(hpaddr >> 12),
                    rvm_pt_flags_to_rv_pt_flags(flags),
                    &mut RVMFrameAllocator,
                )
                .expect("map failed");
            use riscv::addr::AddressX64;
            info!(
                "{:?}",
                self.pt.to_page_table().ref_entry(PageWith::of_addr(
                    riscv::addr::GPAddrSv48X4::new_u64(0x80200000)
                ))
            );
            flusher.flush();
        }
        Ok(())
    }

    /// Unmap the guest physical frame `hpaddr`.
    fn unmap(&mut self, gpaddr: GuestPhysAddr) -> RvmResult {
        let flusher = self
            .pt
            .to_page_table()
            .unmap(PageWith::of_vpn(gpaddr >> 12))?;
        flusher.1.flush();
        Ok(())
    }

    /// Change the `flags` of the guest physical frame `gpaddr`.
    fn protect(&mut self, gpaddr: GuestPhysAddr, flags: impl IntoRvmPageTableFlags) -> RvmResult {
        use riscv::paging::PTE;
        let mut pt = self.pt.to_page_table();
        let entry = pt.ref_entry(PageWith::of_vpn(gpaddr >> 12))?;
        let f = entry.flags_mut();
        *f = rvm_pt_flags_to_rv_pt_flags(flags);
        Ok(())
    }

    /// Query the host physical address which the guest physical frame of
    /// `gpaddr` maps to.
    fn query(&mut self, gpaddr: GuestPhysAddr) -> RvmResult<HostPhysAddr> {
        use riscv::paging::PTE;
        let mut pt = self.pt.to_page_table();
        let entry = pt.ref_entry(PageWith::of_vpn(gpaddr >> 12))?;
        Ok(entry.ppn() << 12)
    }

    /// Page table base address.
    fn table_phys(&self) -> HostPhysAddr {
        self.pt.phys_addr()
    }
}
