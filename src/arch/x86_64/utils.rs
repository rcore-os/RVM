//! Some utility functions.

use bit_field::BitField;
use x86::msr;
use x86_64::registers::{control::Cr0Flags, model_specific::Msr};

use super::vcpu::InterruptState;

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
pub(crate) fn cr0_is_valid(cr0_value: u64, is_unrestricted_guest: bool) -> bool {
    let mut check_value = cr0_value;
    // From Volume 3, Section 26.3.1.1: PE and PG bits of CR0 are not checked when unrestricted
    // guest is enabled. Set both here to avoid clashing with X86_MSR_IA32_VMX_CR0_FIXED1.
    if is_unrestricted_guest {
        check_value |= (Cr0Flags::PAGING | Cr0Flags::PROTECTED_MODE_ENABLE).bits();
    }
    cr_is_valid(
        check_value,
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

/// Get TR base.
pub unsafe fn tr_base(tr: u16) -> u64 {
    let mut dtp = x86::dtables::DescriptorTablePointer::new(&0u64);
    llvm_asm!("sgdt ($0)" :: "r"(&mut dtp) : "memory" : "volatile");
    let tss_descriptor = (dtp.base as usize + tr as usize) as *mut u64;
    let low = tss_descriptor.read();
    let high = tss_descriptor.add(1).read();
    let mut tr_base = 0u64;
    tr_base.set_bits(0..24, low.get_bits(16..40));
    tr_base.set_bits(24..32, low.get_bits(56..64));
    tr_base.set_bits(32..64, high.get_bits(0..32));
    tr_base
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
struct IDTGateEntry {
    pointer_low: u16,
    gdt_selector: u16,
    options: u16,
    pointer_middle: u16,
    pointer_high: u32,
    reserved: u32,
}

impl IDTGateEntry {
    fn get_handler_addr(&self) -> u64 {
        self.pointer_low as u64
            | (self.pointer_middle as u64) << 16
            | (self.pointer_high as u64) << 32
    }
}

/// Call external interrupt handler manually without actually issuing interrupt
pub unsafe fn manual_trap(vector: u8, interrupt_state: &InterruptState) {
    let entries: &'static [IDTGateEntry; 256] = core::mem::transmute(interrupt_state.host_idt_base);
    let target_addr = entries[vector as usize].get_handler_addr();
    #[cfg(target_arch = "x86_64")]
    asm!("
        mov r8, ss              # save ss -> r8
        mov r9, rsp             # save rsp -> r9
        pushf
        pop r10                 # save rlags -> r10
        mov r11, cs             # save cs -> r11

        push r8                 # ss
        push r9                 # rsp
        push r10                # rflags
        push r11                # cs
        call {0}                # push rip and jmp",
        in(reg) target_addr,
        out("r8") _,
        out("r9") _,
        out("r10") _,
        out("r11") _,
    );
}
