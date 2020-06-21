//! Virtual Machine Control Structures.

use bitflags::bitflags;
use x86_64::{instructions::vmx, PhysAddr};

use crate::arch::interrupt;
use crate::rvm::{RvmError, RvmResult};

/// 16-Bit VMCS Fields.
#[repr(usize)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub enum VmcsField16 {
    VIRTUAL_PROCESSOR_ID = 0x00000000,
    POSTED_INTR_NV = 0x00000002,
    GUEST_ES_SELECTOR = 0x00000800,
    GUEST_CS_SELECTOR = 0x00000802,
    GUEST_SS_SELECTOR = 0x00000804,
    GUEST_DS_SELECTOR = 0x00000806,
    GUEST_FS_SELECTOR = 0x00000808,
    GUEST_GS_SELECTOR = 0x0000080a,
    GUEST_LDTR_SELECTOR = 0x0000080c,
    GUEST_TR_SELECTOR = 0x0000080e,
    GUEST_INTR_STATUS = 0x00000810,
    GUEST_PML_INDEX = 0x00000812,
    HOST_ES_SELECTOR = 0x00000c00,
    HOST_CS_SELECTOR = 0x00000c02,
    HOST_SS_SELECTOR = 0x00000c04,
    HOST_DS_SELECTOR = 0x00000c06,
    HOST_FS_SELECTOR = 0x00000c08,
    HOST_GS_SELECTOR = 0x00000c0a,
    HOST_TR_SELECTOR = 0x00000c0c,
}

/// 64-Bit VMCS Fields.
#[repr(usize)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub enum VmcsField64 {
    IO_BITMAP_A = 0x00002000,
    IO_BITMAP_A_HIGH = 0x00002001,
    IO_BITMAP_B = 0x00002002,
    IO_BITMAP_B_HIGH = 0x00002003,
    MSR_BITMAP = 0x00002004,
    MSR_BITMAP_HIGH = 0x00002005,
    VM_EXIT_MSR_STORE_ADDR = 0x00002006,
    VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
    VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
    VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
    VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
    VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
    PML_ADDRESS = 0x0000200e,
    PML_ADDRESS_HIGH = 0x0000200f,
    TSC_OFFSET = 0x00002010,
    TSC_OFFSET_HIGH = 0x00002011,
    VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
    VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
    APIC_ACCESS_ADDR = 0x00002014,
    APIC_ACCESS_ADDR_HIGH = 0x00002015,
    POSTED_INTR_DESC_ADDR = 0x00002016,
    POSTED_INTR_DESC_ADDR_HIGH = 0x00002017,
    VM_FUNCTION_CONTROL = 0x00002018,
    VM_FUNCTION_CONTROL_HIGH = 0x00002019,
    EPT_POINTER = 0x0000201a,
    EPT_POINTER_HIGH = 0x0000201b,
    EOI_EXIT_BITMAP0 = 0x0000201c,
    EOI_EXIT_BITMAP0_HIGH = 0x0000201d,
    EOI_EXIT_BITMAP1 = 0x0000201e,
    EOI_EXIT_BITMAP1_HIGH = 0x0000201f,
    EOI_EXIT_BITMAP2 = 0x00002020,
    EOI_EXIT_BITMAP2_HIGH = 0x00002021,
    EOI_EXIT_BITMAP3 = 0x00002022,
    EOI_EXIT_BITMAP3_HIGH = 0x00002023,
    EPTP_LIST_ADDRESS = 0x00002024,
    EPTP_LIST_ADDRESS_HIGH = 0x00002025,
    VMREAD_BITMAP = 0x00002026,
    VMREAD_BITMAP_HIGH = 0x00002027,
    VMWRITE_BITMAP = 0x00002028,
    VMWRITE_BITMAP_HIGH = 0x00002029,
    XSS_EXIT_BITMAP = 0x0000202C,
    XSS_EXIT_BITMAP_HIGH = 0x0000202D,
    ENCLS_EXITING_BITMAP = 0x0000202E,
    ENCLS_EXITING_BITMAP_HIGH = 0x0000202F,
    TSC_MULTIPLIER = 0x00002032,
    TSC_MULTIPLIER_HIGH = 0x00002033,
    GUEST_PHYSICAL_ADDRESS = 0x00002400,
    GUEST_PHYSICAL_ADDRESS_HIGH = 0x00002401,
    VMCS_LINK_POINTER = 0x00002800,
    VMCS_LINK_POINTER_HIGH = 0x00002801,
    GUEST_IA32_DEBUGCTL = 0x00002802,
    GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
    GUEST_IA32_PAT = 0x00002804,
    GUEST_IA32_PAT_HIGH = 0x00002805,
    GUEST_IA32_EFER = 0x00002806,
    GUEST_IA32_EFER_HIGH = 0x00002807,
    GUEST_IA32_PERF_GLOBAL_CTRL = 0x00002808,
    GUEST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002809,
    GUEST_PDPTR0 = 0x0000280a,
    GUEST_PDPTR0_HIGH = 0x0000280b,
    GUEST_PDPTR1 = 0x0000280c,
    GUEST_PDPTR1_HIGH = 0x0000280d,
    GUEST_PDPTR2 = 0x0000280e,
    GUEST_PDPTR2_HIGH = 0x0000280f,
    GUEST_PDPTR3 = 0x00002810,
    GUEST_PDPTR3_HIGH = 0x00002811,
    GUEST_BNDCFGS = 0x00002812,
    GUEST_BNDCFGS_HIGH = 0x00002813,
    GUEST_IA32_RTIT_CTL = 0x00002814,
    GUEST_IA32_RTIT_CTL_HIGH = 0x00002815,
    HOST_IA32_PAT = 0x00002c00,
    HOST_IA32_PAT_HIGH = 0x00002c01,
    HOST_IA32_EFER = 0x00002c02,
    HOST_IA32_EFER_HIGH = 0x00002c03,
    HOST_IA32_PERF_GLOBAL_CTRL = 0x00002c04,
    HOST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002c05,
}

/// 32-Bit VMCS Fields.
#[repr(usize)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub enum VmcsField32 {
    PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
    CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
    EXCEPTION_BITMAP = 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
    CR3_TARGET_COUNT = 0x0000400a,
    VM_EXIT_CONTROLS = 0x0000400c,
    VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
    VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
    VM_ENTRY_CONTROLS = 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
    VM_ENTRY_INTR_INFO = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
    VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
    TPR_THRESHOLD = 0x0000401c,
    SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
    PLE_GAP = 0x00004020,
    PLE_WINDOW = 0x00004022,
    VM_INSTRUCTION_ERROR = 0x00004400,
    VM_EXIT_REASON = 0x00004402,
    VM_EXIT_INTR_INFO = 0x00004404,
    VM_EXIT_INTR_ERROR_CODE = 0x00004406,
    IDT_VECTORING_INFO = 0x00004408,
    IDT_VECTORING_ERROR_CODE = 0x0000440a,
    VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
    VMX_INSTRUCTION_INFO = 0x0000440e,
    GUEST_ES_LIMIT = 0x00004800,
    GUEST_CS_LIMIT = 0x00004802,
    GUEST_SS_LIMIT = 0x00004804,
    GUEST_DS_LIMIT = 0x00004806,
    GUEST_FS_LIMIT = 0x00004808,
    GUEST_GS_LIMIT = 0x0000480a,
    GUEST_LDTR_LIMIT = 0x0000480c,
    GUEST_TR_LIMIT = 0x0000480e,
    GUEST_GDTR_LIMIT = 0x00004810,
    GUEST_IDTR_LIMIT = 0x00004812,
    GUEST_ES_AR_BYTES = 0x00004814,
    GUEST_CS_AR_BYTES = 0x00004816,
    GUEST_SS_AR_BYTES = 0x00004818,
    GUEST_DS_AR_BYTES = 0x0000481a,
    GUEST_FS_AR_BYTES = 0x0000481c,
    GUEST_GS_AR_BYTES = 0x0000481e,
    GUEST_LDTR_AR_BYTES = 0x00004820,
    GUEST_TR_AR_BYTES = 0x00004822,
    GUEST_INTERRUPTIBILITY_STATE = 0x00004824,
    GUEST_ACTIVITY_STATE = 0x00004826,
    GUEST_IA32_SYSENTER_CS = 0x0000482A,
    VMX_PREEMPTION_TIMER_VALUE = 0x0000482E,
    HOST_IA32_SYSENTER_CS = 0x00004c00,
}

/// Natural-Width VMCS Fields.
#[repr(usize)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub enum VmcsFieldXX {
    CR0_GUEST_HOST_MASK = 0x00006000,
    CR4_GUEST_HOST_MASK = 0x00006002,
    CR0_READ_SHADOW = 0x00006004,
    CR4_READ_SHADOW = 0x00006006,
    CR3_TARGET_VALUE0 = 0x00006008,
    CR3_TARGET_VALUE1 = 0x0000600a,
    CR3_TARGET_VALUE2 = 0x0000600c,
    CR3_TARGET_VALUE3 = 0x0000600e,
    EXIT_QUALIFICATION = 0x00006400,
    GUEST_LINEAR_ADDRESS = 0x0000640a,
    GUEST_CR0 = 0x00006800,
    GUEST_CR3 = 0x00006802,
    GUEST_CR4 = 0x00006804,
    GUEST_ES_BASE = 0x00006806,
    GUEST_CS_BASE = 0x00006808,
    GUEST_SS_BASE = 0x0000680a,
    GUEST_DS_BASE = 0x0000680c,
    GUEST_FS_BASE = 0x0000680e,
    GUEST_GS_BASE = 0x00006810,
    GUEST_LDTR_BASE = 0x00006812,
    GUEST_TR_BASE = 0x00006814,
    GUEST_GDTR_BASE = 0x00006816,
    GUEST_IDTR_BASE = 0x00006818,
    GUEST_DR7 = 0x0000681a,
    GUEST_RSP = 0x0000681c,
    GUEST_RIP = 0x0000681e,
    GUEST_RFLAGS = 0x00006820,
    GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
    GUEST_IA32_SYSENTER_ESP = 0x00006824,
    GUEST_IA32_SYSENTER_EIP = 0x00006826,
    HOST_CR0 = 0x00006c00,
    HOST_CR3 = 0x00006c02,
    HOST_CR4 = 0x00006c04,
    HOST_FS_BASE = 0x00006c06,
    HOST_GS_BASE = 0x00006c08,
    HOST_TR_BASE = 0x00006c0a,
    HOST_GDTR_BASE = 0x00006c0c,
    HOST_IDTR_BASE = 0x00006c0e,
    HOST_IA32_SYSENTER_ESP = 0x00006c10,
    HOST_IA32_SYSENTER_EIP = 0x00006c12,
    HOST_RSP = 0x00006c14,
    HOST_RIP = 0x00006c16,
}

bitflags! {
    /// Definitions of Pin-Based VM-Execution Controls.
    pub struct PinBasedVmExecControls: u32 {
        /// VM-Exit on vectored interrupts
        const INTR_EXITING      = 1 << 0;
        /// VM-Exit on NMIs
        const NMI_EXITING       = 1 << 3;
        /// NMI virtualization
        const VIRTUAL_NMIS      = 1 << 5;
        /// VMX Preemption Timer
        const PREEMPTION_TIMER  = 1 << 6;
        /// Posted Interrupts
        const POSTED_INTR       = 1 << 7;
    }
}

bitflags! {
    /// Definitions of Primary Processor-Based VM-Execution Controls.
    pub struct CpuBasedVmExecControls: u32 {
        /// VM-Exit if INTRs are unblocked in guest
        const INTR_WINDOW_EXITING   = 1 <<  2;
        /// Offset hardware TSC when read in guest
        const USE_TSC_OFFSETTING    = 1 <<  3;
        /// VM-Exit on HLT
        const HLT_EXITING           = 1 <<  7;
        /// VM-Exit on INVLPG
        const INVLPG_EXITING        = 1 <<  9;
        /// VM-Exit on MWAIT
        const MWAIT_EXITING         = 1 << 10;
        /// VM-Exit on RDPMC
        const RDPMC_EXITING         = 1 << 11;
        /// VM-Exit on RDTSC
        const RDTSC_EXITING         = 1 << 12;
        /// VM-Exit on writes to CR3
        const CR3_LOAD_EXITING      = 1 << 15;
        /// VM-Exit on reads from CR3
        const CR3_STORE_EXITING     = 1 << 16;
        /// VM-Exit on writes to CR8
        const CR8_LOAD_EXITING      = 1 << 19;
        /// VM-Exit on reads from CR8
        const CR8_STORE_EXITING     = 1 << 20;
        /// TPR virtualization, a.k.a. TPR shadow
        const VIRTUAL_TPR           = 1 << 21;
        /// VM-Exit if NMIs are unblocked in guest
        const NMI_WINDOW_EXITING    = 1 << 22;
        /// VM-Exit on accesses to debug registers
        const MOV_DR_EXITING        = 1 << 23;
        /// VM-Exit on *all* IN{S} and OUT{S}
        const UNCOND_IO_EXITING     = 1 << 24;
        /// VM-Exit based on I/O port
        const USE_IO_BITMAPS        = 1 << 25;
        /// VMX single-step VM-Exits
        const MONITOR_TRAP_FLAG     = 1 << 27;
        /// VM-Exit based on MSR index
        const USE_MSR_BITMAPS       = 1 << 28;
        /// M-Exit on MONITOR (MWAIT's accomplice)
        const MONITOR_EXITING       = 1 << 29;
        /// VM-Exit on PAUSE (unconditionally)
        const PAUSE_EXITING         = 1 << 30;
        /// Enable Secondary VM-Execution Controls
        const SEC_CONTROLS          = 1 << 31;
    }
}

bitflags! {
    /// Definitions of Secondary Processor-Based VM-Execution Controls.
    pub struct SecondaryCpuBasedVmExecControls: u32 {
        /// Virtualize memory mapped APIC accesses
        const VIRT_APIC_ACCESSES    = 1 <<  0;
        /// Extended Page Tables, a.k.a. Two-Dimensional Paging
        const EPT                   = 1 <<  1;
        /// VM-Exit on {S,L}*DT instructions
        const DESC_EXITING          = 1 <<  2;
        /// Enable RDTSCP in guest
        const RDTSCP                = 1 <<  3;
        /// Virtualize X2APIC for the guest
        const VIRTUAL_X2APIC        = 1 <<  4;
        /// Virtual Processor ID (TLB ASID modifier)
        const VPID                  = 1 <<  5;
        /// VM-Exit on WBINVD
        const WBINVD_EXITING        = 1 <<  6;
        /// Allow Big Real Mode and other "invalid" states
        const UNRESTRICTED_GUEST    = 1 <<  7;
        /// Hardware emulation of reads to the virtual-APIC
        const APIC_REGISTER_VIRT    = 1 <<  8;
        /// Evaluation and delivery of pending virtual interrupts
        const VIRT_INTR_DELIVERY    = 1 <<  9;
        /// Conditionally VM-Exit on PAUSE at CPL0
        const PAUSE_LOOP_EXITING    = 1 << 10;
        /// VM-Exit on RDRAND
        const RDRAND_EXITING        = 1 << 11;
        /// Enable INVPCID in guest
        const INVPCID               = 1 << 12;
        /// Enable VM-Functions (leaf dependent)
        const VMFUNC                = 1 << 13;
        /// VMREAD/VMWRITE in guest can access shadow VMCS
        const SHADOW_VMCS           = 1 << 14;
        /// VM-Exit on ENCLS (leaf dependent)
        const ENCLS_EXITING         = 1 << 15;
        /// VM-Exit on RDSEED
        const RDSEED_EXITING        = 1 << 16;
        /// Log dirty pages into buffer
        const PAGE_MOD_LOGGING      = 1 << 17;
        /// Conditionally reflect EPT violations as #VE exceptions
        const EPT_VIOLATION_VE      = 1 << 18;
        /// Suppress VMX indicators in Processor Trace
        const PT_CONCEAL_VMX        = 1 << 19;
        /// Enable XSAVES and XRSTORS in guest
        const XSAVES                = 1 << 20;
        /// Enable separate EPT EXEC bits for supervisor vs. user
        const MODE_BASED_EPT_EXEC   = 1 << 22;
        /// Processor Trace logs GPAs
        const PT_USE_GPA            = 1 << 24;
        /// Scale hardware TSC when read in guest
        const TSC_SCALING           = 1 << 25;
        /// Enable TPAUSE, UMONITOR, UMWAIT in guest
        const USR_WAIT_PAUSE        = 1 << 26;
        /// VM-Exit on ENCLV (leaf dependent)
        const ENCLV_EXITING         = 1 << 28;
    }
}

bitflags! {
    /// Definitions of VM-Exit Controls.
    pub struct VmExitControls: u32 {
        const SAVE_DEBUG_CONTROLS           = 1 <<  2;
        /// Logical processor is in 64-bit mode after VM exit.
        const HOST_ADDR_SPACE_SIZE          = 1 <<  9;
        const LOAD_IA32_PERF_GLOBAL_CTRL    = 1 << 12;
        /// Acknowledge external interrupt on exit.
        const ACK_INTR_ON_EXIT              = 1 << 15;
        /// Save the guest IA32_PAT MSR on exit.
        const SAVE_IA32_PAT                 = 1 << 18;
        /// Load the guest IA32_PAT MSR on exit.
        const LOAD_IA32_PAT                 = 1 << 19;
        /// Save the guest IA32_EFER MSR on exit.
        const SAVE_IA32_EFER                = 1 << 20;
        /// LoaLoad the host IA32_EFER MSR on exit.
        const LOAD_IA32_EFER                = 1 << 21;
        const SAVE_VMX_PREEMPTION_TIMER     = 1 << 22;
        const CLEAR_BNDCFGS                 = 1 << 23;
        const PT_CONCEAL_PIP                = 1 << 24;
        const CLEAR_IA32_RTIT_CTL           = 1 << 25;
        const LOAD_CET_STATE                = 1 << 28;
    }
}

bitflags! {
    /// Definitions of VM-Entry Controls.
    pub struct VmEntryControls: u32 {
        const LOAD_DEBUG_CONTROLS           = 1 <<  2;
        const IA32E_MODE                    = 1 <<  9;
        const SMM                           = 1 << 10;
        const DEACT_DUAL_MONITOR            = 1 << 11;
        const LOAD_IA32_PERF_GLOBAL_CTRL    = 1 << 13;
        /// Load the guest IA32_PAT MSR on entry.
        const LOAD_IA32_PAT                 = 1 << 14;
        /// Load the guest IA32_EFER MSR on entry.
        const LOAD_IA32_EFER                = 1 << 15;
        const LOAD_BNDCFGS                  = 1 << 16;
        const PT_CONCEAL_PIP                = 1 << 17;
        const LOAD_IA32_RTIT_CTL            = 1 << 18;
        const LOAD_CET_STATE                = 1 << 20;
    }
}

bitflags! {
    /// Access rights for VMCS guest register states.
    ///
    /// The low 16 bits correspond to bits 23:8 of the upper 32 bits of a 64-bit
    /// segment descriptor. See Volume 3, Section 24.4.1 for access rights format,
    /// Volume 3, Section 3.4.5.1 for valid non-system selector types, Volume 3,
    /// Section 3.5 for valid system selectors types.
    pub struct GuestRegisterAccessRights: u32 {
        /// Accessed flag.
        const ACCESSED          = 1 << 0;
        /// For data segments, this flag sets the segment as writable. For code
        /// segments, this flag sets the segment as readable.
        const WRITABLE          = 1 << 1;
        /// For data segments, this flag marks a data segment as “expansion-direction”.
        /// For code segments, this flag marks a code segment as “conforming”.
        const CONFORMING        = 1 << 2;
        /// This flag must be set for code segments.
        const EXECUTABLE        = 1 << 3;
        /// S — Descriptor type (0 = system; 1 = code or data)
        const CODE_DATA         = 1 << 4;
        /// P — Segment present
        const PRESENT           = 1 << 7;
        /// L - Reserved (except for CS) or 64-bit mode active (for CS only)
        const LONG_MODE         = 1 << 13;
        /// D/B — Default operation size (0 = 16-bit segment; 1 = 32-bit segment)
        const DB                = 1 << 14;
        /// G — Granularity
        const GRANULARITY       = 1 << 15;
        /// Segment unusable (0 = usable; 1 = unusable)
        const UNUSABLE          = 1 << 16;

        /// 16-bit TSS (Busy)
        const TSS_BUSY_16       = 0b0011;
        /// TSS (Busy) for 32/64-bit
        const TSS_BUSY          = 0b1011;
    }
}

impl Default for GuestRegisterAccessRights {
    fn default() -> Self {
        Self::ACCESSED | Self::WRITABLE | Self::CODE_DATA | Self::PRESENT
    }
}

bitflags! {
    /// The IA-32 architecture includes features that permit certain events to
    /// be blocked for a period of time. This field contains information about
    /// such blocking.
    pub struct InterruptibilityState: u32 {
        /// Execution of STI with RFLAGS.IF = 0 blocks maskable interrupts on
        /// the instruction boundary following its execution. Setting this bit
        /// indicates that this blocking is in effect.
        const BLOCKING_BY_STI       = 1 << 0;
        /// Execution of a MOV to SS or a POP to SS blocks or suppresses certain
        /// debug exceptions as well as interrupts (maskable and nonmaskable) on
        /// the instruction boundary following its execution. Setting this bit
        /// indicates that this blocking is in effect. by MOV SS,” but it applies
        /// equally to POP SS.
        const BLOCKING_BY_MOV_SS    = 1 << 1;
        /// System-management interrupts (SMIs) are disabled while the processor
        /// is in system-management mode (SMM). Setting this bit indicates that
        /// blocking of SMIs is in effect.
        const BLOCKING_BY_SMI       = 1 << 2;
        /// Delivery of a non-maskable interrupt (NMI) or a system-management
        /// interrupt (SMI) blocks subsequent NMIs until the next execution of
        /// IRET. See Section 25.3 for how this behavior of IRET may change in
        /// VMX non-root operation. Setting this bit indicates that blocking of
        /// NMIs is in effect. Clearing this bit does not imply that NMIs are
        /// not (temporarily) blocked for other reasons.
        const BLOCKING_BY_NMI       = 1 << 3;
        /// Such VM exits includes those caused by interrupts, non-maskable
        /// interrupts, system- management interrupts, INIT signals, and exceptions
        /// occurring in enclave mode as well as exceptions encountered during
        /// the delivery of such events incident to enclave mode.
        const ENCLAVE_INTERRUPTION  = 1 << 4;
    }
}

bitflags! {
    /// This field provides details about the event to be injected.
    pub struct InterruptionInfo: u32 {
        /// External interrupt
        const TYPE_EXTERNAL             = 0 << 8;
        /// Non-maskable interrupt (NMI)
        const TYPE_NMI                  = 2 << 8;
        /// Hardware exception (e.g,. #PF)
        const TYPE_HARD_EXCEPTION       = 3 << 8;
        /// Software interrupt (INT n)
        const TYPE_SOFT_INTR            = 4 << 8;
        /// Privileged software exception (INT1)
        const TYPE_PRIV_SOFT_EXCEPTION  = 5 << 8;
        /// Software exception (INT3 or INTO)
        const TYPE_SOFT_EXCEPTION       = 6 << 8;
        /// Other event
        const TYPE_OTHER                = 7 << 8;
        /// Deliver error code
        const ERROR_CODE                = 1 << 12;
        /// Valid
        const VALID                     = 1 << 31;
    }
}

impl InterruptionInfo {
    fn has_error_code(vector: u8) -> bool {
        use crate::arch::interrupt::consts as int_num;
        match vector {
            int_num::DoubleFault
            | int_num::InvalidTSS
            | int_num::SegmentNotPresent
            | int_num::StackSegmentFault
            | int_num::GeneralProtectionFault
            | int_num::PageFault
            | int_num::AlignmentCheck => true,
            _ => false,
        }
    }

    fn from_vector(vector: u8) -> Self {
        use crate::arch::interrupt::consts as int_num;
        let mut info = unsafe { Self::from_bits_unchecked(vector as u32) } | Self::VALID;
        match vector {
            int_num::NonMaskableInterrupt => info |= Self::TYPE_NMI,
            // From Volume 3, Section 24.8.3. A VMM should use type hardware exception for all
            // exceptions other than breakpoints and overflows, which should be software exceptions.
            int_num::Breakpoint | int_num::Overflow => info |= Self::TYPE_SOFT_EXCEPTION,
            // From Volume 3, Section 6.15. All other vectors from 0 to 21 are exceptions.
            0..=int_num::VirtualizationException => info |= Self::TYPE_HARD_EXCEPTION,
            _ => {}
        };
        if Self::has_error_code(vector) {
            info |= Self::ERROR_CODE;
        }
        info
    }
}

/// Loads a VMCS within a given scope.
#[derive(Debug)]
pub struct AutoVmcs {
    vmcs_paddr: u64,
    interrupt_flags: usize,
}

impl AutoVmcs {
    pub fn new(phys_addr: PhysAddr) -> RvmResult<Self> {
        unsafe {
            let interrupt_flags = interrupt::disable_and_store();
            if vmx::vmptrld(phys_addr).is_none() {
                interrupt::restore(interrupt_flags);
                Err(RvmError::DeviceError)
            } else {
                trace!("[RVM] interrupts disabled");
                Ok(Self {
                    vmcs_paddr: phys_addr.as_u64(),
                    interrupt_flags,
                })
            }
        }
    }

    pub fn _invalidate(&mut self) {
        self.vmcs_paddr = 0;
    }

    pub fn interrupt_window_exiting(&mut self, enable: bool) {
        let mut ctrl = unsafe {
            CpuBasedVmExecControls::from_bits_unchecked(
                self.read32(VmcsField32::CPU_BASED_VM_EXEC_CONTROL),
            )
        };
        ctrl.set(CpuBasedVmExecControls::INTR_WINDOW_EXITING, enable);
        self.write32(VmcsField32::CPU_BASED_VM_EXEC_CONTROL, ctrl.bits());
    }

    pub fn issue_interrupt(&mut self, vector: u8) {
        let info = InterruptionInfo::from_vector(vector);
        if info.contains(InterruptionInfo::ERROR_CODE) {
            self.write32(VmcsField32::VM_ENTRY_EXCEPTION_ERROR_CODE, 0);
        }
        self.write32(VmcsField32::VM_ENTRY_INTR_INFO, info.bits());
    }

    pub fn read16(&self, field: VmcsField16) -> u16 {
        self.read(field as usize) as u16
    }

    pub fn read32(&self, field: VmcsField32) -> u32 {
        self.read(field as usize) as u32
    }

    pub fn read64(&self, field: VmcsField64) -> u64 {
        #[cfg(target_pointer_width = "64")]
        return self.read(field as usize) as u64;
        #[cfg(target_pointer_width = "32")]
        return self.read(field as usize) as u64 | (self.read(field as usize + 1) as u64) << 32;
    }

    #[allow(non_snake_case)]
    pub fn readXX(&self, field: VmcsFieldXX) -> usize {
        self.read(field as usize)
    }

    pub fn write16(&mut self, field: VmcsField16, value: u16) {
        self.write(field as usize, value as usize);
    }

    pub fn write32(&mut self, field: VmcsField32, value: u32) {
        self.write(field as usize, value as usize);
    }

    pub fn write64(&mut self, field: VmcsField64, value: u64) {
        self.write(field as usize, value as usize);
        #[cfg(target_pointer_width = "32")]
        self.write(field as usize + 1, (value >> 32) as usize);
    }

    #[allow(non_snake_case)]
    pub fn writeXX(&mut self, field: VmcsFieldXX, value: usize) {
        self.write(field as usize, value);
    }

    pub fn set_control(
        &mut self,
        field: VmcsField32,
        true_msr: u64,
        old_msr: u64,
        set: u32,
        clear: u32,
    ) -> RvmResult<()> {
        debug_assert!(self.vmcs_paddr != 0);
        let allowed_0 = true_msr as u32;
        let allowed_1 = (true_msr >> 32) as u32;
        if (allowed_1 & set) != set {
            warn!("[RVM] can not set vmcs controls {:?}", field);
            return Err(RvmError::NotSupported);
        }
        if (!allowed_0 & clear) != clear {
            warn!("[RVM] can not clear vmcs controls {:?}", field);
            return Err(RvmError::NotSupported);
        }
        if (set & clear) != 0 {
            warn!(
                "[RVM] can not set and clear the same vmcs controls {:?}",
                field
            );
            return Err(RvmError::InvalidParam);
        }

        // See Volume 3, Section 31.5.1, Algorithm 3, Part C. If the control can be
        // either 0 or 1 (flexible), and the control is unknown, then refer to the
        // old MSR to find the default value.
        let flexible = allowed_0 ^ allowed_1;
        let unknown = flexible & !(set | clear);
        let defaults = unknown & old_msr as u32;
        self.write32(field, allowed_0 | defaults | set);
        Ok(())
    }

    #[inline]
    fn read(&self, field: usize) -> usize {
        debug_assert!(self.vmcs_paddr != 0);
        unsafe {
            vmx::vmread(field).unwrap_or_else(|| {
                panic!("[RVM] vmread error: field={:#x}", field);
            })
        }
    }

    #[inline]
    fn write(&mut self, field: usize, value: usize) {
        debug_assert!(self.vmcs_paddr != 0);
        unsafe {
            if vmx::vmwrite(field, value).is_none() {
                warn!(
                    "[RVM] vmwrite error: field={:#x}, value={:#x}",
                    field, value
                );
            }
        }
    }
}

impl Drop for AutoVmcs {
    fn drop(&mut self) {
        unsafe { interrupt::restore(self.interrupt_flags) };
        trace!("[RVM] interrupts enabled");
    }
}
