//! Model specific registers used for VMX.
//!
//! See Volume 3, Appendix A: VMX Capability Reporting Facility for detail.

#![allow(dead_code)]

use bit_field::BitField;
use bitflags::bitflags;

pub use x86_64::registers::model_specific::Msr;

trait MsrReadWrite {
    const MSR: Msr;

    /// Read the current raw MSR flags.
    #[inline]
    fn read_raw() -> u64 {
        unsafe { Self::MSR.read() }
    }

    /// Write the MSR flags.
    ///
    /// Does not preserve any bits, including reserved fields.
    #[inline]
    unsafe fn write_raw(flags: u64) {
        let mut msr = Self::MSR;
        msr.write(flags);
    }
}

bitflags! {
    /// MSR_IA32_FEATURE_CONTROL flags.
   pub struct VmxBasicFlags: u64 {
       /// The processor reports information in the VM-exit instruction-
       /// information field on VM exits due to execution of the INS and OUTS
       /// instructions (see Section 27.2.5). This reporting is done only if
       /// this bit is read as 1.
       const IO_EXIT_INFO = 1 << 54;
       /// Any VMX controls that default to 1 may be cleared to 0. See Appendix
       /// A.2 for details. It also reports support for the VMX capability MSRs
       /// IA32_VMX_TRUE_PINBASED_CTLS, IA32_VMX_TRUE_PROCBASED_CTLS,
       /// IA32_VMX_TRUE_EXIT_CTLS, and IA32_VMX_TRUE_ENTRY_CTLS.
       const VMX_FLEX_CONTROLS = 1 << 55;
   }
}

/// Stores VMX info from the IA32_VMX_BASIC MSR.
#[derive(Debug)]
pub struct VmxBasic {
    pub revision_id: u32,
    pub region_size: u16,
    pub write_back: bool,
    pub io_exit_info: bool,
    pub vmx_flex_controls: bool,
}

impl MsrReadWrite for VmxBasic {
    const MSR: Msr = Msr::new(x86::msr::IA32_VMX_BASIC);
}

impl VmxBasic {
    /// Read the current IA32_VMX_BASIC flags.
    #[inline]
    pub fn read() -> Self {
        const VMX_MEMORY_TYPE_WRITE_BACK: u64 = 6;
        let msr = Self::read_raw();
        let flags = VmxBasicFlags::from_bits_truncate(msr);
        Self {
            revision_id: msr.get_bits(0..31) as u32,
            region_size: msr.get_bits(32..45) as u16,
            write_back: msr.get_bits(50..54) == VMX_MEMORY_TYPE_WRITE_BACK,
            io_exit_info: flags.contains(VmxBasicFlags::IO_EXIT_INFO),
            vmx_flex_controls: flags.contains(VmxBasicFlags::VMX_FLEX_CONTROLS),
        }
    }
}

bitflags! {
     /// MSR_IA32_FEATURE_CONTROL flags.
    pub struct FeatureControlFlags: u64 {
        /// Lock bit: when set, locks this MSR from being written.
        const LOCKED = 1 << 0;
        /// Enable VMX inside SMX operation.
        const VMXON_ENABLED_INSIDE_SMX = 1 << 1;
        /// Enable VMX outside SMX operation.
        const VMXON_ENABLED_OUTSIDE_SMX = 1 << 2;
    }
}

/// Control Features in Intel 64 Processor: MSR_IA32_FEATURE_CONTROL
#[derive(Debug)]
pub struct FeatureControl;

impl MsrReadWrite for FeatureControl {
    const MSR: Msr = Msr::new(x86::msr::IA32_FEATURE_CONTROL);
}

impl FeatureControl {
    /// Read the current MSR_IA32_FEATURE_CONTROL flags.
    #[inline]
    pub fn read() -> FeatureControlFlags {
        FeatureControlFlags::from_bits_truncate(Self::read_raw())
    }

    /// Write MSR_IA32_FEATURE_CONTROL flags, preserving reserved values.
    ///
    /// Preserves the value of reserved fields.
    pub unsafe fn write(flags: FeatureControlFlags) {
        let old_value = Self::read_raw();
        let reserved = old_value & !(FeatureControlFlags::all().bits());
        let new_value = reserved | flags.bits();

        Self::write_raw(new_value);
    }

    /// Update MSR_IA32_FEATURE_CONTROL flags.
    ///
    /// Preserves the value of reserved fields.
    pub unsafe fn update<F>(f: F)
    where
        F: FnOnce(&mut FeatureControlFlags),
    {
        let mut flags = Self::read();
        f(&mut flags);
        Self::write(flags);
    }
}
