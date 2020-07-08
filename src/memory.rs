pub type GuestPhysAddr = usize;
pub type HostPhysAddr = usize;
pub type HostVirtAddr = usize;

pub fn alloc_frame() -> Option<HostPhysAddr> {
    unsafe { rvm_extern_fn::rvm_alloc_frame() }
}

pub fn dealloc_frame(paddr: HostPhysAddr) {
    unsafe { rvm_extern_fn::rvm_dealloc_frame(paddr) }
}

/// Convert physical address to virtual address
pub fn phys_to_virt(paddr: HostPhysAddr) -> HostVirtAddr {
    unsafe { rvm_extern_fn::rvm_phys_to_virt(paddr) }
}

mod rvm_extern_fn {
    use super::*;

    extern "Rust" {
        pub fn rvm_alloc_frame() -> Option<HostPhysAddr>;
        pub fn rvm_dealloc_frame(_paddr: HostPhysAddr);
        pub fn rvm_phys_to_virt(_paddr: HostPhysAddr) -> HostVirtAddr;
    }
}
