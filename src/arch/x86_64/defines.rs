//! VMX constants definition.

use core::fmt::{Debug, Formatter, Result};
use numeric_enum_macro::numeric_enum;

numeric_enum! {
    #[repr(u32)]
    #[derive(Debug)]
    #[allow(dead_code)]
    #[allow(non_camel_case_types)]
    pub enum ExitReason {
        EXCEPTION_OR_NMI = 0,
        EXTERNAL_INTERRUPT = 1,
        TRIPLE_FAULT = 2,
        INIT_SIGNAL = 3,
        STARTUP_IPI = 4,
        IO_SMI = 5,
        OTHER_SMI = 6,
        INTERRUPT_WINDOW = 7,
        NMI_WINDOW = 8,
        TASK_SWITCH = 9,
        CPUID = 10,
        GETSEC = 11,
        HLT = 12,
        INVD = 13,
        INVLPG = 14,
        RDPMC = 15,
        RDTSC = 16,
        RSM = 17,
        VMCALL = 18,
        VMCLEAR = 19,
        VMLAUNCH = 20,
        VMPTRLD = 21,
        VMPTRST = 22,
        VMREAD = 23,
        VMRESUME = 24,
        VMWRITE = 25,
        VMXOFF = 26,
        VMXON = 27,
        CONTROL_REGISTER_ACCESS = 28,
        MOV_DR = 29,
        IO_INSTRUCTION = 30,
        RDMSR = 31,
        WRMSR = 32,
        ENTRY_FAILURE_GUEST_STATE = 33,
        ENTRY_FAILURE_MSR_LOADING = 34,
        MWAIT = 36,
        MONITOR_TRAP_FLAG = 37,
        MONITOR = 39,
        PAUSE = 40,
        ENTRY_FAILURE_MACHINE_CHECK = 41,
        TPR_BELOW_THRESHOLD = 43,
        APIC_ACCESS = 44,
        VIRTUALIZED_EOI = 45,
        ACCESS_GDTR_OR_IDTR = 46,
        ACCESS_LDTR_OR_TR = 47,
        EPT_VIOLATION = 48,
        EPT_MISCONFIGURATION = 49,
        INVEPT = 50,
        RDTSCP = 51,
        VMX_PREEMPT_TIMER_EXPIRED = 52,
        INVVPID = 53,
        WBINVD = 54,
        XSETBV = 55,
        APIC_WRITE = 56,
        RDRAND = 57,
        INVPCID = 58,
        VMFUNC = 59,
        ENCLS = 60,
        RDSEED = 61,
        PAGE_MODIFICATION_LOG_FULL = 62,
        XSAVES = 63,
        XRSTORS = 64,
        SPP_EVENT = 66,
        UMWAIT = 67,
        TPAUSE = 68,
    }
}

pub struct VmInstructionError {
    number: u32,
}

impl VmInstructionError {
    fn explain(&self) -> &str {
        match self.number {
            0 => "OK",
            1 => "VMCALL executed in VMX root operation",
            2 => "VMCLEAR with invalid physical address",
            3 => "VMCLEAR with VMXON pointer",
            4 => "VMLAUNCH with non-clear VMCS",
            5 => "VMRESUME with non-launched VMCS",
            6 => "VMRESUME after VMXOFF (VMXOFF and VMXON between VMLAUNCH and VMRESUME)",
            7 => "VM entry with invalid control field(s)",
            8 => "VM entry with invalid host-state field(s)",
            9 => "VMPTRLD with invalid physical address",
            10 => "VMPTRLD with VMXON pointer",
            11 => "VMPTRLD with incorrect VMCS revision identifier",
            12 => "VMREAD/VMWRITE from/to unsupported VMCS component",
            13 => "VMWRITE to read-only VMCS component",
            15 => "VMXON executed in VMX root operation",
            16 => "VM entry with invalid executive-VMCS pointer",
            17 => "VM entry with non-launched executive VMCS",
            18 => "VM entry with executive-VMCS pointer not VMXON pointer (when attempting to deactivate the dual-monitor treatment of SMIs and SMM)",
            19 => "VMCALL with non-clear VMCS (when attempting to activate the dual-monitor treatment of SMIs and SMM)",
            20 => "VMCALL with invalid VM-exit control fields",
            22 => "VMCALL with incorrect MSEG revision identifier (when attempting to activate the dual-monitor treatment of SMIs and SMM)",
            23 => "VMXOFF under dual-monitor treatment of SMIs and SMM",
            24 => "VMCALL with invalid SMM-monitor features (when attempting to activate the dual-monitor treatment of SMIs and SMM)",
            25 => "VM entry with invalid VM-execution control fields in executive VMCS (when attempting to return from SMM)",
            26 => "VM entry with events blocked by MOV SS",
            28 => "Invalid operand to INVEPT/INVVPID",
            _ => "[INVALID]",
        }
    }
}

impl From<u32> for VmInstructionError {
    fn from(x: u32) -> Self {
        VmInstructionError { number: x }
    }
}

impl Debug for VmInstructionError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            "VmInstructionError({}, {:?})",
            self.number,
            self.explain()
        )
    }
}

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
