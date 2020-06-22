pub type GuestPhysAddr = usize;
pub type HostPhysAddr = usize;
pub type HostVirtAddr = usize;

pub fn alloc_frame() -> Option<HostPhysAddr> {
    unsafe { ffi::alloc_frame() }
}

pub fn dealloc_frame(paddr: HostPhysAddr) {
    unsafe { ffi::dealloc_frame(paddr) }
}

/// Convert physical address to virtual address
pub fn phys_to_virt(paddr: HostPhysAddr) -> HostVirtAddr {
    unsafe { ffi::phys_to_virt(paddr) }
}

mod ffi {
    use super::*;

    extern "C" {
        pub fn alloc_frame() -> Option<HostPhysAddr>;
        pub fn dealloc_frame(_paddr: HostPhysAddr);
        pub fn phys_to_virt(_paddr: HostPhysAddr) -> HostVirtAddr;
    }
}
