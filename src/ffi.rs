use crate::{HostPhysAddr, HostVirtAddr};

/// Allocate contiguous physical frames
/// RISC-V requires 16KB-aligned first level page table for GPA translation.
pub fn alloc_frames(n: usize) -> Option<HostPhysAddr> {
    unsafe { rvm_alloc_frames(n) }
}

/// Deallocate contiguous physical frames
/// The page count `n` must match with allocation.
pub fn dealloc_frames(paddr: HostPhysAddr, n: usize) {
    unsafe { rvm_dealloc_frames(paddr, n) }
}

/// Allocate one physical frame
pub fn alloc_frame() -> Option<HostPhysAddr> {
    alloc_frames(1)
}

/// Deallocate one physical frame
pub fn dealloc_frame(paddr: HostPhysAddr) {
    dealloc_frames(paddr, 1)
}

/// Allocate 4 contiguous physical frames
/// RISC-V requires 16KB-aligned first level page table for GPA translation.
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
pub fn alloc_frame_x4() -> Option<HostPhysAddr> {
    alloc_frames(4)
}

/// Deallocate 4 contiguous physical frames
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
pub fn dealloc_frame_x4(paddr: HostPhysAddr) {
    dealloc_frames(paddr, 4)
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

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
pub fn riscv_trap_handler_no_frame(sepc: usize) {
    let mut sepc_new = sepc;
    unsafe { rvm_riscv_trap_handler_no_frame(&mut sepc_new) }
    if sepc_new != sepc {
        panic!("user_fixup called in trap handler, which should not happen for a vm trap.");
    }
}
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
pub fn riscv_check_hypervisor_extension() -> bool {
    unsafe { rvm_riscv_check_hypervisor_extension() }
}

extern "Rust" {
    fn rvm_alloc_frames(_n: usize) -> Option<HostPhysAddr>;
    fn rvm_dealloc_frames(_paddr: HostPhysAddr, _n: usize);
    fn rvm_phys_to_virt(_paddr: HostPhysAddr) -> HostVirtAddr;

    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    fn rvm_riscv_check_hypervisor_extension() -> bool;
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    fn rvm_riscv_trap_handler_no_frame(sepc: &mut usize);

    #[cfg(target_arch = "x86_64")]
    fn rvm_is_host_timer_interrupt(vector: u8) -> bool;
    #[cfg(target_arch = "x86_64")]
    fn rvm_is_host_serial_interrupt(vector: u8) -> bool;

}
