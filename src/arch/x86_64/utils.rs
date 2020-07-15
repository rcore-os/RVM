//! Some utility functions.

use x86::msr;
use x86_64::registers::model_specific::Msr;

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct InvEptDescriptor {
    /// EPT pointer (EPTP)
    eptp: u64,
    reserved: u64,
}

#[repr(u64)]
#[derive(Debug)]
#[allow(dead_code)]
pub enum InvEptType {
    /// The logical processor invalidates all mappings associated with bits
    /// 51:12 of the EPT pointer (EPTP) specified in the INVEPT descriptor.
    /// It may invalidate other mappings as well.
    SingleContext = 1,

    /// The logical processor invalidates mappings associated with all EPTPs.
    Global = 2,
}

pub unsafe fn invept(invalidation: InvEptType, eptp: u64) -> Option<()> {
    let err: bool;
    let descriptor = InvEptDescriptor { eptp, reserved: 0 };
    llvm_asm!("invept ($1), $2; setna $0" : "=r" (err) : "r" (&descriptor), "r" (invalidation) : "cc", "memory" : "volatile");

    if err {
        None
    } else {
        Some(())
    }
}

/// Check whether the CR0/CR4 has required fixed bits.
fn cr_is_valid(cr_value: u64, fixed0_msr: u32, fixed1_msr: u32) -> bool {
    let fixed0 = unsafe { Msr::new(fixed0_msr).read() };
    let fixed1 = unsafe { Msr::new(fixed1_msr).read() };
    ((cr_value & fixed1) | fixed0) == cr_value
}

/// Check whether the CR0 has required fixed bits.
pub(crate) fn cr0_is_valid(cr0_value: u64) -> bool {
    cr_is_valid(
        cr0_value,
        msr::IA32_VMX_CR0_FIXED0,
        msr::IA32_VMX_CR0_FIXED1,
    )
}

/// Check whether the CR4 has required fixed bits.
pub(crate) fn cr4_is_valid(cr4_value: u64) -> bool {
    cr_is_valid(
        cr4_value,
        msr::IA32_VMX_CR4_FIXED0,
        msr::IA32_VMX_CR4_FIXED1,
    )
}
