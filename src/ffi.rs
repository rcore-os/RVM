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

/// Whether need to inject timer interrupt to guest when an interrupt occurs on host
#[cfg(target_arch = "x86_64")]
pub fn is_host_timer_interrupt(vector: u8) -> bool {
    unsafe { rvm_is_host_timer_interrupt(vector) }
}

/// Whether need to inject serial interrupt to guest when an interrupt occurs on host
#[cfg(target_arch = "x86_64")]
pub fn is_host_serial_interrupt(vector: u8) -> bool {
    unsafe { rvm_is_host_serial_interrupt(vector) }
}

extern "Rust" {
    fn rvm_alloc_frame() -> Option<HostPhysAddr>;
    fn rvm_dealloc_frame(_paddr: HostPhysAddr);
    fn rvm_phys_to_virt(_paddr: HostPhysAddr) -> HostVirtAddr;
    #[cfg(target_arch = "x86_64")]
    fn rvm_is_host_timer_interrupt(vector: u8) -> bool;
    #[cfg(target_arch = "x86_64")]
    fn rvm_is_host_serial_interrupt(vector: u8) -> bool;
}
