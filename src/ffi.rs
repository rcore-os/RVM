use crate::{HostPhysAddr, HostVirtAddr};

pub fn alloc_frame() -> Option<HostPhysAddr> {
    unsafe { rvm_alloc_frame() }
}

pub fn dealloc_frame(paddr: HostPhysAddr) {
    unsafe { rvm_dealloc_frame(paddr) }
}

// RISC-V requires 16KB-aligned first level page table for GPA translation.
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
pub fn alloc_frame_x4() -> Option<HostPhysAddr> {
    unsafe { rvm_alloc_frame_x4() }
}
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
pub fn dealloc_frame_x4(paddr: HostPhysAddr) {
    unsafe { rvm_dealloc_frame_x4(paddr) }
}

/// Convert physical address to virtual address
pub fn phys_to_virt(paddr: HostPhysAddr) -> HostVirtAddr {
    unsafe { rvm_phys_to_virt(paddr) }
}

/// The address where the hardware jumps to when an interrupt occurs, only used on x86.
#[cfg(target_arch = "x86_64")]
pub fn x86_all_traps_handler_addr() -> usize {
    unsafe { rvm_x86_all_traps_handler_addr() }
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
    fn rvm_alloc_frame() -> Option<HostPhysAddr>;
    fn rvm_dealloc_frame(_paddr: HostPhysAddr);
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    fn rvm_alloc_frame_x4() -> Option<HostPhysAddr>;
    fn rvm_dealloc_frame_x4(_paddr: HostPhysAddr);
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    fn rvm_phys_to_virt(_paddr: HostPhysAddr) -> HostVirtAddr;
    #[cfg(target_arch = "x86_64")]
    fn rvm_x86_all_traps_handler_addr() -> usize;
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    fn rvm_riscv_check_hypervisor_extension() -> bool;
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    fn rvm_riscv_trap_handler_no_frame(sepc: &mut usize);
}
