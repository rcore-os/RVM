pub type GuestPhysAddr = usize;
pub type HostPhysAddr = usize;
pub type HostVirtAddr = usize;

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn alloc_frame() -> Option<HostPhysAddr> {
    unimplemented!()
}

#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn dealloc_frame(_paddr: HostPhysAddr) {
    unimplemented!()
}

/// Convert physical address to virtual address
#[no_mangle]
#[linkage = "weak"]
pub extern "C" fn phys_to_virt(_paddr: HostPhysAddr) -> HostVirtAddr {
    unimplemented!()
}
