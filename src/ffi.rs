use crate::{HostPhysAddr, HostVirtAddr};

/// Allocate physical frame
pub fn alloc_frame() -> Option<HostPhysAddr> {
    unsafe { rvm_alloc_frame() }
}

/// Deallocate physical frame
pub fn dealloc_frame(paddr: HostPhysAddr) {
    unsafe { rvm_dealloc_frame(paddr) }
}

/// Convert physical address to virtual address
pub fn phys_to_virt(paddr: HostPhysAddr) -> HostVirtAddr {
    unsafe { rvm_phys_to_virt(paddr) }
}

extern "Rust" {
    fn rvm_alloc_frame() -> Option<HostPhysAddr>;
    fn rvm_dealloc_frame(_paddr: HostPhysAddr);
    fn rvm_phys_to_virt(_paddr: HostPhysAddr) -> HostVirtAddr;
}
