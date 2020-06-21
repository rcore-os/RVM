//! Model specific registers used for VMX.
//!
//! See Volume 3, Appendix A: VMX Capability Reporting Facility for detail.

#![allow(dead_code)]

use bit_field::BitField;
use bitflags::bitflags;

pub use x86_64::registers::model_specific::Msr;

/// Control Features in Intel 64 Processor.
pub const MSR_IA32_FEATURE_CONTROL: u32 = 0x003a;

/// Per Logical Processor TSC Adjust (R/Write to clear)
pub const MSR_IA32_TSC_ADJUST: u32 = 0x003b;

/// IA32_PAT (R/W)
pub const MSR_IA32_PAT: u32 = 0x0277;

/// Basic VMX information.
pub const MSR_IA32_VMX_BASIC: u32 = 0x0480;

/// Pin-Based VM-Execution Controls.
pub const MSR_IA32_VMX_PINBASED_CTLS: u32 = 0x0481;

/// Primary Processor-Based VM-Execution Controls.
pub const MSR_IA32_VMX_PROCBASED_CTLS: u32 = 0x0482;

/// VM-Exit Controls.
pub const MSR_IA32_VMX_EXIT_CTLS: u32 = 0x0483;

/// VM-Entry Controls.
pub const MSR_IA32_VMX_ENTRY_CTLS: u32 = 0x0484;

/// Miscellaneous info.
pub const MSR_IA32_VMX_MISC: u32 = 0x0485;

/// CR0 bits that must be 0 to enter VMX.
pub const MSR_IA32_VMX_CR0_FIXED0: u32 = 0x0486;

/// CR0 bits that must be 1 to enter VMX
pub const MSR_IA32_VMX_CR0_FIXED1: u32 = 0x0487;

/// CR4 bits that must be 0 to enter VMX.
pub const MSR_IA32_VMX_CR4_FIXED0: u32 = 0x0488;

/// CR4 bits that must be 1 to enter VMX.
pub const MSR_IA32_VMX_CR4_FIXED1: u32 = 0x0489;

/// Secondary Processor-Based VM-Execution Controls.
pub const MSR_IA32_VMX_PROCBASED_CTLS2: u32 = 0x048b;

/// VPID and EPT Capabilities.
pub const MSR_IA32_VMX_EPT_VPID_CAP: u32 = 0x048c;

/// Pin-Based VM-Execution Flex Controls.
pub const MSR_IA32_VMX_TRUE_PINBASED_CTLS: u32 = 0x048d;

/// Primary Processor-Based VM-Execution Flex Controls.
pub const MSR_IA32_VMX_TRUE_PROCBASED_CTLS: u32 = 0x048e;

/// VM-Exit Flex Controls.
pub const MSR_IA32_VMX_TRUE_EXIT_CTLS: u32 = 0x048f;

/// VM-Entry Flex Controls.
pub const MSR_IA32_VMX_TRUE_ENTRY_CTLS: u32 = 0x0490;

/// Extended Feature Enables
pub const MSR_IA32_EFER: u32 = 0xc000_0080;

/// System Call Target Address (R/W)
pub const MSR_IA32_STAR: u32 = 0xc000_0081;

/// IA-32e Mode System Call Target Address (R/W)
pub const MSR_IA32_LSTAR: u32 = 0xc000_0082;

/// System Call Flag Mask (R/W)
pub const MSR_IA32_FMASK: u32 = 0xc000_0084;

/// Map of BASE Address of FS (R/W)
pub const MSR_IA32_FS_BASE: u32 = 0xc000_0100;

/// Map of BASE Address of GS (R/W)
pub const MSR_IA32_GS_BASE: u32 = 0xc000_0101;

/// Swap Target of BASE Address of GS (R/W)
pub const MSR_IA32_KERNEL_GS_BASE: u32 = 0xc000_0102;

/// AUXILIARY TSC Signature (R/W)
pub const MSR_IA32_TSC_AUX: u32 = 0xc000_0103;

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
        Self::MSR.write(flags);
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
    const MSR: Msr = Msr::new(MSR_IA32_VMX_BASIC);
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
    const MSR: Msr = Msr::new(MSR_IA32_FEATURE_CONTROL);
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
