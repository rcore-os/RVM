//! VM exit handler

use alloc::sync::Arc;
use bit_field::BitField;
use core::convert::TryInto;
use numeric_enum_macro::numeric_enum;
use spin::Mutex;
use x86::msr;
use x86_64::registers::{control::Cr0Flags, model_specific::EferFlags};

use super::feature::*;
use super::msr::Msr;
use super::structs::ExitReason;
use super::utils::{cr0_is_valid, manual_trap};
use super::vcpu::{GuestState, InterruptState};
use super::vmcall::VmcallStatus;
use super::vmcs::{
    AutoVmcs, GuestRegisterAccessRights, InterruptibilityState,
    SecondaryCpuBasedVmExecControls as CpuCtrl2, VmEntryControls, VmcsField16::*, VmcsField32::*,
    VmcsField64::*, VmcsFieldXX::*,
};
use crate::memory::GuestPhysMemorySetTrait;
use crate::packet::*;
use crate::trap_map::{TrapKind, TrapMap};
use crate::{RvmError, RvmResult};

type ExitResult = RvmResult<Option<RvmExitPacket>>;

const VENDOR_STRING: &str = "KVMKVMKVM\0\0\0";

const K_FIRST_EXTENDED_STATE_COMPONENT: u32 = 2;
const K_LAST_EXTENDED_STATE_COMPONENT: u32 = 9;
// From Volume 1, Section 13.4.
const K_XSAVE_LEGACY_REGION_SIZE: u32 = 512;
const K_XSAVE_HEADER_SIZE: u32 = 64;

const K_PROCBASED_CTLS2_INVPCID: u32 = 1 << 12;

#[derive(Debug)]
struct ExitInfo {
    entry_failure: bool,
    exit_reason: ExitReason,
    exit_instruction_length: u32,
    exit_qualification: usize,
    guest_rip: usize,
}

impl ExitInfo {
    fn from(vmcs: &AutoVmcs) -> Self {
        let full_reason = vmcs.read32(VM_EXIT_REASON);
        Self {
            exit_reason: full_reason.get_bits(0..16).try_into().unwrap(),
            entry_failure: full_reason.get_bit(31),
            exit_instruction_length: vmcs.read32(VM_EXIT_INSTRUCTION_LEN),
            exit_qualification: vmcs.readXX(EXIT_QUALIFICATION),
            guest_rip: vmcs.readXX(GUEST_RIP),
        }
    }

    fn next_rip(&self, vmcs: &mut AutoVmcs) {
        vmcs.writeXX(
            GUEST_RIP,
            self.guest_rip + self.exit_instruction_length as usize,
        );
        use InterruptibilityState as IntrState;
        let old = IntrState::from_bits_truncate(vmcs.read32(GUEST_INTERRUPTIBILITY_STATE));
        let mut new = old;
        new.remove(IntrState::BLOCKING_BY_STI | IntrState::BLOCKING_BY_MOV_SS);
        if new != old {
            vmcs.write32(GUEST_INTERRUPTIBILITY_STATE, new.bits())
        }
    }
}

#[derive(Debug)]
struct ExitInterruptionInfo {
    vector: u8,
    interruption_type: u8,
    valid: bool,
}

impl ExitInterruptionInfo {
    fn from(vmcs: &AutoVmcs) -> Self {
        let info = vmcs.read32(VM_EXIT_INTR_INFO);
        Self {
            vector: info.get_bits(0..8) as u8,
            interruption_type: info.get_bits(8..11) as u8,
            valid: info.get_bit(31),
        }
    }
}

numeric_enum! {
    #[repr(u8)]
    #[derive(Debug)]
    enum CrAccessType {
        MovToCr = 0,
        MovFromCr = 1,
        CLTS = 2,
        LMSW = 3,
    }
}

#[derive(Debug)]
struct CrAccessInfo {
    cr_num: u8,
    access_type: CrAccessType,
    reg: u8,
}

impl CrAccessInfo {
    fn from(qualification: usize) -> Self {
        Self {
            cr_num: qualification.get_bits(0..4) as u8,
            access_type: (qualification.get_bits(4..6) as u8).try_into().unwrap(),
            reg: qualification.get_bits(8..12) as u8,
        }
    }
}

#[derive(Debug)]
struct EptViolationInfo {
    read: bool,
    write: bool,
    instruction: bool,
}

impl EptViolationInfo {
    fn from(qualification: usize) -> Self {
        Self {
            read: qualification.get_bit(0),
            write: qualification.get_bit(1),
            instruction: qualification.get_bit(2),
        }
    }
}

#[derive(Debug)]
struct IoInfo {
    access_size: u8,
    input: bool,
    string: bool,
    repeat: bool,
    port: u16,
}

impl IoInfo {
    fn from(qualification: usize) -> Self {
        Self {
            access_size: qualification.get_bits(0..3) as u8 + 1,
            input: qualification.get_bit(3),
            string: qualification.get_bit(4),
            repeat: qualification.get_bit(5),
            port: qualification.get_bits(16..32) as u16,
        }
    }
}

fn handle_external_interrupt(vmcs: &AutoVmcs, interrupt_state: &mut InterruptState) -> ExitResult {
    let info = ExitInterruptionInfo::from(vmcs);
    trace!("[RVM] VM exit: External interrupt {:#x?}", info);
    debug_assert!(info.valid);
    debug_assert!(info.interruption_type == 0);

    unsafe { manual_trap(info.vector, interrupt_state) };

    use super::consts::{COM1, IRQ0};
    if crate::ffi::is_host_timer_interrupt(info.vector) {
        interrupt_state.timer_irq();
    }
    if crate::ffi::is_host_serial_interrupt(info.vector) {
        interrupt_state
            .controller
            .virtual_interrupt((IRQ0 + COM1) as usize);
    }

    Ok(None)
}

fn handle_interrupt_window(vmcs: &mut AutoVmcs) -> ExitResult {
    vmcs.interrupt_window_exiting(false);
    Ok(None)
}

fn handle_cpuid(
    exit_info: &ExitInfo,
    vmcs: &mut AutoVmcs,
    guest_state: &mut GuestState,
) -> ExitResult {
    let leaf: u32 = guest_state.rax as u32;
    let subleaf: u32 = guest_state.rcx as u32;

    exit_info.next_rip(vmcs);

    const X86_CPUID_BASE: u32 = X86CpuidLeafNum::BASE as u32;
    const X86_CPUID_EXT_BASE: u32 = X86CpuidLeafNum::EXT_BASE as u32;
    const X86_CPUID_BASE_PLUS_ONE: u32 = X86_CPUID_BASE + 1;
    const X86_CPUID_EXT_BASE_PLUS_ONE: u32 = X86_CPUID_EXT_BASE + 1;
    const X86_CPUID_MODEL_FEATURES: u32 = X86CpuidLeafNum::MODEL_FEATURES as u32;
    const X86_CPUID_TOPOLOGY: u32 = X86CpuidLeafNum::TOPOLOGY as u32;
    const X86_CPUID_XSAVE: u32 = X86CpuidLeafNum::XSAVE as u32;
    const X86_CPUID_THERMAL_AND_POWER: u32 = X86CpuidLeafNum::THERMAL_AND_POWER as u32;
    const X86_CPUID_PERFORMANCE_MONITORING: u32 = X86CpuidLeafNum::PERFORMANCE_MONITORING as u32;
    const X86_CPUID_MON: u32 = X86CpuidLeafNum::MON as u32;
    const X86_CPUID_EXTENDED_FEATURE_FLAGS: u32 = X86CpuidLeafNum::EXTENDED_FEATURE_FLAGS as u32;
    const X86_CPUID_HYP_BASE: u32 = X86CpuidLeafNum::HYP_BASE as u32;
    const X86_CPUID_KVM_FEATURES: u32 = X86CpuidLeafNum::KVM_FEATURES as u32;

    match leaf {
        X86_CPUID_BASE | X86_CPUID_EXT_BASE => {
            cpuid(leaf, guest_state);
            Ok(None)
        }
        X86_CPUID_BASE_PLUS_ONE..=MAX_SUPPORTED_CPUID
        | X86_CPUID_EXT_BASE_PLUS_ONE..=MAX_SUPPORTED_CPUID_EXT => {
            cpuid_c(leaf, subleaf, guest_state);
            match leaf {
                X86_CPUID_MODEL_FEATURES => {
                    // Override the initial local APIC ID. From Vol 2, Table 3-8.
                    guest_state
                        .rbx
                        .set_bits(24..32, (vmcs.read16(VIRTUAL_PROCESSOR_ID) - 1) as u64);
                    // Enable the hypervisor bit.
                    guest_state.rcx.set_bit(X86_FEATURE_HYPERVISOR.bit, true);
                    // Enable the x2APIC bit.
                    guest_state.rcx.set_bit(X86_FEATURE_X2APIC.bit, true);
                    // Disable the VMX bit.
                    guest_state.rcx.set_bit(X86_FEATURE_VMX.bit, false);
                    // Disable the PDCM bit.
                    guest_state.rcx.set_bit(X86_FEATURE_PDCM.bit, false);
                    // Disable MONITOR/MWAIT.
                    guest_state.rcx.set_bit(X86_FEATURE_MON.bit, false);
                    // Disable THERM_INTERRUPT and THERM_STATUS MSRs
                    guest_state.rcx.set_bit(X86_FEATURE_TM2.bit, false);
                    // Enable the SEP (SYSENTER support).
                    guest_state.rdx.set_bit(X86_FEATURE_SEP.bit, true);
                    // Disable the Thermal Monitor bit.
                    guest_state.rdx.set_bit(X86_FEATURE_TM.bit, false);
                    // Disable the THERM_CONTROL_MSR bit.
                    guest_state.rdx.set_bit(X86_FEATURE_ACPI.bit, false);
                }
                X86_CPUID_TOPOLOGY => {
                    guest_state.rdx = (vmcs.read16(VIRTUAL_PROCESSOR_ID) - 1) as u64;
                }
                X86_CPUID_XSAVE => {
                    if subleaf == 0 {
                        let xsave_size = compute_xsave_size(guest_state.xcr0);
                        guest_state.rbx = xsave_size as u64;
                    } else if subleaf == 1 {
                        guest_state.rax.set_bit(3, false);
                    }
                }
                X86_CPUID_THERMAL_AND_POWER => {
                    // Disable the performance energy bias bit.
                    guest_state.rcx.set_bit(X86_FEATURE_PERF_BIAS.bit, false);
                    // Disable the hardware coordination feedback bit.
                    guest_state.rcx.set_bit(X86_FEATURE_HW_FEEDBACK.bit, false);
                    // Disable Digital Thermal Sensor
                    guest_state.rax.set_bit(X86_FEATURE_DTS.bit, false);
                    // Disable Package Thermal Status MSR.
                    guest_state.rax.set_bit(X86_FEATURE_PTM.bit, false);
                    // Disable THERM_STATUS MSR bits 10/11 & THERM_INTERRUPT MSR bit 24
                    // Disable HWP MSRs.
                    guest_state.rax.set_bit(X86_FEATURE_HWP.bit, false);
                    guest_state.rax.set_bit(X86_FEATURE_HWP_NOT.bit, false);
                    guest_state.rax.set_bit(X86_FEATURE_HWP_ACT.bit, false);
                    guest_state.rax.set_bit(X86_FEATURE_HWP_PREF.bit, false);
                }
                X86_CPUID_PERFORMANCE_MONITORING => {
                    // Disable all performance monitoring.
                    // 31-07 = Reserved 0, 06-00 = 1 if event is not available.
                    const PERFORMANCE_MONITORING_NO_EVENTS: u32 = 0b1111111;
                    guest_state.rax = 0;
                    guest_state.rbx = PERFORMANCE_MONITORING_NO_EVENTS as u64;
                    guest_state.rcx = 0;
                    guest_state.rdx = 0;
                }
                X86_CPUID_MON => {
                    // MONITOR/MWAIT are not implemented.
                    guest_state.rax = 0;
                    guest_state.rbx = 0;
                    guest_state.rcx = 0;
                    guest_state.rdx = 0;
                }
                X86_CPUID_EXTENDED_FEATURE_FLAGS => {
                    // It's possible when running under KVM in nVMX mode, that host
                    // CPUID indicates that invpcid is supported but VMX doesn't allow
                    // to enable INVPCID bit in secondary processor based controls.
                    // Therefore explicitly clear INVPCID bit in CPUID if the VMX flag
                    // wasn't set.
                    // FIXME: here vmcs.read32(PROCBASED_CTLS2) in zircon
                    if (vmcs.read32(SECONDARY_VM_EXEC_CONTROL) & K_PROCBASED_CTLS2_INVPCID) == 0 {
                        guest_state.rbx.set_bit(X86_FEATURE_INVPCID.bit, false);
                    }
                    // Disable the Processor Trace bit.
                    guest_state.rbx.set_bit(X86_FEATURE_PT.bit, false);
                    // Disable:
                    //  * Indirect Branch Prediction Barrier bit
                    //  * Single Thread Indirect Branch Predictors bit
                    //  * Speculative Store Bypass Disable bit
                    // These imply support for the IA32_SPEC_CTRL and IA32_PRED_CMD
                    // MSRs, which are not implemented.
                    guest_state.rdx.set_bit(X86_FEATURE_IBRS_IBPB.bit, false);
                    guest_state.rdx.set_bit(X86_FEATURE_STIBP.bit, false);
                    guest_state.rdx.set_bit(X86_FEATURE_SSBD.bit, false);
                    // Disable support of IA32_ARCH_CAPABILITIES MSR.
                    guest_state
                        .rdx
                        .set_bit(X86_FEATURE_ARCH_CAPABILITIES.bit, false);
                }
                _ => unreachable!(),
            };
            Ok(None)
        }
        X86_CPUID_HYP_BASE => {
            // This leaf is commonly used to identify a hypervisor via ebx:ecx:edx.

            // Since Zircon hypervisor disguises itself as KVM, it needs to return
            // in EAX max CPUID function supported by hypervisor. Zero in EAX
            // should be interpreted as 0x40000001. Details are available in the
            // Linux kernel documentation (Documentation/virtual/kvm/cpuid.txt).
            guest_state.rax = X86_CPUID_KVM_FEATURES as u64;
            #[allow(clippy::cast_ptr_alignment)]
            let vendor_id = unsafe { &*(VENDOR_STRING.as_ptr() as *const [u32; 3]) };
            guest_state.rbx = vendor_id[0] as u64;
            guest_state.rcx = vendor_id[1] as u64;
            guest_state.rdx = vendor_id[2] as u64;
            Ok(None)
        }
        X86_CPUID_KVM_FEATURES => {
            // We support KVM clock. // FIXME
            // guest_state.rax = kKvmFeatureClockSourceOld | kKvmFeatureClockSource | kKvmFeatureNoIoDelay;
            guest_state.rax = 0;
            guest_state.rbx = 0;
            guest_state.rcx = 0;
            guest_state.rdx = 0;
            Ok(None)
        }
        _ => {
            cpuid_c(MAX_SUPPORTED_CPUID, subleaf, guest_state);
            Ok(None)
        }
    }
}

fn compute_xsave_size(guest_xcr0: u64) -> u32 {
    let mut xsave_size = K_XSAVE_LEGACY_REGION_SIZE + K_XSAVE_HEADER_SIZE;
    for i in K_FIRST_EXTENDED_STATE_COMPONENT..=K_LAST_EXTENDED_STATE_COMPONENT {
        if !guest_xcr0.get_bit(i as usize) {
            continue;
        }
        let leaf = raw_cpuid::cpuid!(X86CpuidLeafNum::XSAVE as u32, i);
        if leaf.eax == 0 && leaf.ebx == 0 && leaf.ecx == 0 && leaf.edx == 0 {
            continue;
        }
        let component_offset = leaf.ebx;
        let component_size = leaf.eax;
        xsave_size = component_offset + component_size;
    }
    xsave_size
}

fn handle_vmcall(
    exit_info: &ExitInfo,
    vmcs: &mut AutoVmcs,
    guest_state: &mut GuestState,
) -> ExitResult {
    exit_info.next_rip(vmcs);
    let num = guest_state.rax;
    let args = [
        guest_state.rbx,
        guest_state.rcx,
        guest_state.rdx,
        guest_state.rsi,
    ];

    let access_rights = vmcs.read32(GUEST_SS_AR_BYTES);
    if access_rights & GuestRegisterAccessRights::DPL_USER.bits() != 0 {
        guest_state.rax = VmcallStatus::NotPermitted as u64;
        return Ok(None);
    }

    let [a0, a1, a2, a3] = args;
    let status = super::vmcall::vmcall(num, a0, a1, a2, a3);
    guest_state.rax = status as u64;
    Ok(None)
}

fn handle_hlt(exit_info: &ExitInfo, vmcs: &mut AutoVmcs) -> ExitResult {
    exit_info.next_rip(vmcs);
    // TODO: wait for interrupt
    Ok(None)
}

fn handle_pause(exit_info: &ExitInfo, vmcs: &mut AutoVmcs) -> ExitResult {
    exit_info.next_rip(vmcs);
    Ok(None)
}

fn handle_cr0_write(
    val: Cr0Flags,
    vmcs: &mut AutoVmcs,
    interrupt_state: &mut InterruptState,
) -> RvmResult {
    // X86_CR0_NE is masked so that guests may write to it, but depending on
    // IA32_VMX_CR0_FIXED0 it might be unsupported in VMX operation to set it to
    // zero. Allow the guest to control its value in CR0_READ_SHADOW but not in
    // GUEST_CR0 so that GUEST_CR0 stays valid.
    let mut cr0 = val | Cr0Flags::NUMERIC_ERROR;
    let is_unrestricted_guest =
        CpuCtrl2::from_bits_truncate(vmcs.read32(SECONDARY_VM_EXEC_CONTROL))
            .contains(CpuCtrl2::UNRESTRICTED_GUEST);
    if !cr0_is_valid(cr0.bits(), is_unrestricted_guest) {
        return Err(RvmError::InvalidParam);
    }

    // From Volume 3, Table 11-5: CD=0 and NW=1 is an invalid setting and should
    // generate a GP fault.
    if !val.contains(Cr0Flags::CACHE_DISABLE) && val.contains(Cr0Flags::NOT_WRITE_THROUGH) {
        interrupt_state
            .controller
            .virtual_interrupt(super::consts::GeneralProtectionFault as usize);
        return Ok(());
    }

    // From Volume 3, Section 26.3.2.1: CR0 is loaded from the CR0 field with the
    // exception of the following bits, which are never modified on VM entry: ET
    // (bit 4); reserved bits ...; NW (bit 29) and CD (bit 30). The values of
    // these bits in the CR0 field are ignored.
    //
    // Even though these bits will be ignored on VM entry, to ensure that
    // GUEST_CR0 matches the actual value of CR0 while the guest is running set
    // those bits to match the host values. This is done only to make debugging
    // simpler.
    cr0.remove(Cr0Flags::CACHE_DISABLE | Cr0Flags::NOT_WRITE_THROUGH);
    vmcs.writeXX(GUEST_CR0, cr0.bits() as usize);
    // From Volume 3, Section 25.3: For each position corresponding to a bit clear
    // in the CR0 guest/host mask, the destination operand is loaded with the
    // value of the corresponding bit in CR0. For each position corresponding to a
    // bit set in the CR0 guest/host mask, the destination operand is loaded with
    // the value of the corresponding bit in the CR0 read shadow.
    //
    // Allow the guest to control the shadow.
    vmcs.writeXX(CR0_READ_SHADOW, val.bits() as usize);

    // From Volume 3, Section 26.3.1.1: If CR0.PG and EFER.LME are set then
    // EFER.LMA and the IA-32e mode guest entry control must also be set.
    let efer = EferFlags::from_bits_truncate(vmcs.read64(GUEST_IA32_EFER));
    if !(efer.contains(EferFlags::LONG_MODE_ENABLE) && cr0.contains(Cr0Flags::PAGING)) {
        return Ok(());
    }
    vmcs.write64(GUEST_IA32_EFER, (efer | EferFlags::LONG_MODE_ACTIVE).bits());
    unsafe {
        vmcs.set_control(
            VM_ENTRY_CONTROLS,
            Msr::new(msr::IA32_VMX_TRUE_ENTRY_CTLS).read(),
            Msr::new(msr::IA32_VMX_ENTRY_CTLS).read(),
            VmEntryControls::IA32E_MODE.bits(),
            0,
        )
    }
}

fn handle_cr_access(
    exit_info: &ExitInfo,
    vmcs: &mut AutoVmcs,
    guest_state: &mut GuestState,
    interrupt_state: &mut InterruptState,
) -> ExitResult {
    let cr_info = CrAccessInfo::from(exit_info.exit_qualification);
    match cr_info.access_type {
        CrAccessType::MovToCr => {
            if cr_info.cr_num != 0 {
                return Err(RvmError::NotSupported);
            }
            let val = match cr_info.reg {
                0 => guest_state.rax,
                1 => guest_state.rcx,
                2 => guest_state.rdx,
                3 => guest_state.rbx,
                4 => vmcs.readXX(GUEST_RSP) as u64,
                5 => guest_state.rbp,
                6 => guest_state.rsi,
                7 => guest_state.rdi,
                8 => guest_state.r8,
                9 => guest_state.r9,
                10 => guest_state.r10,
                11 => guest_state.r11,
                12 => guest_state.r12,
                13 => guest_state.r13,
                14 => guest_state.r14,
                15 => guest_state.r15,
                _ => return Err(RvmError::InvalidParam),
            };

            handle_cr0_write(Cr0Flags::from_bits_truncate(val), vmcs, interrupt_state)?;
            exit_info.next_rip(vmcs);
            Ok(None)
        }
        _ => Err(RvmError::NotSupported),
    }
}

fn handle_io_instruction(
    exit_info: &ExitInfo,
    vmcs: &mut AutoVmcs,
    guest_state: &mut GuestState,
    interrupt_state: &mut InterruptState,
    traps: &Mutex<TrapMap>,
) -> ExitResult {
    let io_info = IoInfo::from(exit_info.exit_qualification);
    trace!(
        "[RVM] VM exit: IO instruction @ RIP({:#x}): {} {:#x?}, repeat = {}, string = {}",
        exit_info.guest_rip,
        if io_info.input { "IN" } else { "OUT" },
        io_info.port,
        io_info.repeat,
        io_info.string
    );

    exit_info.next_rip(vmcs);
    match io_info.port {
        // QEMU debug port
        0x402 => {
            if !io_info.input {
                info!("{}", guest_state.rax as u8 as char);
            }
            return Ok(None);
        }
        // i8253 PIT
        0x40 => {
            if io_info.input {
                guest_state.rax = interrupt_state.timer.read() as u64;
            } else {
                interrupt_state.timer.write(guest_state.rax as u8);
            }
            return Ok(None);
        }
        _ => {}
    }

    let trap = match traps
        .lock()
        .find(TrapKind::GuestTrapIo, io_info.port as usize)
    {
        Some(t) => t,
        None => {
            warn!("[RVM] VM exit: Unhandled IO port {:#x}", io_info.port);
            return Ok(None);
        }
    };

    trace!(
        "[RVM] VM exit: Found trap {:#x?} with IO port {:#x}, RAX value: {:#x}",
        trap,
        io_info.port,
        guest_state.rax as u8
    );

    let mut data = [0; 4];
    if io_info.input {
        // From Volume 1, Section 3.4.1.1: 32-bit operands generate a 32-bit
        // result, zero-extended to a 64-bit result in the destination general-
        // purpose register.
        if io_info.access_size == 4 {
            guest_state.rax = 0;
        }
    } else {
        let ptr = &guest_state.rax as *const _ as *const u8;
        let len = io_info.access_size as usize;
        unsafe { data[..len].copy_from_slice(core::slice::from_raw_parts(ptr, len)) };
    }

    Ok(Some(RvmExitPacket::new_io_packet(
        trap.key,
        IoPacket {
            port: io_info.port,
            access_size: io_info.access_size,
            input: io_info.input,
            string: io_info.string,
            repeat: io_info.repeat,
            _padding1: Default::default(),
            data,
        },
    )))
}

/// Check whether the EPT violation is caused by accessing MMIO region.
///
/// Returns:
/// - `Ok(RvmExitPacket)` if it's an MMIO access, need to forward the packet to
///   the userspace handler.
/// - `Ok(None)` if it's an asynchronous MMIO access (bell), send packet via port.
/// - `Err(NotFound)` if it's not an MMIO access, handle it as a normal EPT page fault.
/// - `Err(RvmError)` if an error occurs.
fn handle_mmio(
    exit_info: &ExitInfo,
    ept_vio_info: &EptViolationInfo,
    vmcs: &mut AutoVmcs,
    guest_paddr: usize,
    gpm: &Arc<dyn GuestPhysMemorySetTrait>,
    traps: &Mutex<TrapMap>,
) -> ExitResult {
    if exit_info.exit_instruction_length as usize > super::consts::X86_MAX_INST_LEN {
        return Err(RvmError::Internal);
    }

    let trap = traps
        .lock()
        .find(TrapKind::GuestTrapMem, guest_paddr)
        .ok_or(RvmError::NotFound)?;

    exit_info.next_rip(vmcs);
    match trap.kind {
        TrapKind::GuestTrapBell => {
            if ept_vio_info.read {
                return Err(RvmError::NotSupported);
            }
            if let Some(port) = trap.port {
                let packet = RvmExitPacket::new_bell_packet(trap.key, guest_paddr as u64);
                port.send(packet)?;
                Ok(None)
            } else {
                Err(RvmError::BadState)
            }
        }
        TrapKind::GuestTrapMem => {
            let efer = EferFlags::from_bits_truncate(vmcs.read64(GUEST_IA32_EFER));
            let cs_rights =
                GuestRegisterAccessRights::from_bits_truncate(vmcs.read32(GUEST_CS_AR_BYTES));
            let default_operand_size = if (efer.contains(EferFlags::LONG_MODE_ACTIVE)
                && cs_rights.contains(GuestRegisterAccessRights::LONG_MODE))
                || cs_rights.contains(GuestRegisterAccessRights::DB)
            {
                4 // IA32-e 64 bit mode, or CS.D set (and not 64 bit mode).
            } else {
                2 // CS.D clear (and not 64 bit mode).
            };
            let mut packet = MmioPacket {
                addr: guest_paddr as u64,
                inst_len: exit_info.exit_instruction_length as u8,
                default_operand_size,
                ..Default::default()
            };
            // FIXME: read via guest vaddr
            gpm.read_memory(
                exit_info.guest_rip,
                &mut packet.inst_buf[..packet.inst_len as usize],
            )?;
            Ok(Some(RvmExitPacket::new_mmio_packet(trap.key, packet)))
        }
        _ => Err(RvmError::BadState),
    }
}

fn handle_ept_violation(
    exit_info: &ExitInfo,
    vmcs: &mut AutoVmcs,
    gpm: &Arc<dyn GuestPhysMemorySetTrait>,
    traps: &Mutex<TrapMap>,
) -> ExitResult {
    let ept_vio_info = EptViolationInfo::from(exit_info.exit_qualification);
    let guest_paddr = vmcs.read64(GUEST_PHYSICAL_ADDRESS) as usize;
    trace!(
        "[RVM] VM exit: EPT violation @ {:#x} RIP({:#x})",
        guest_paddr,
        exit_info.guest_rip
    );

    match handle_mmio(exit_info, &ept_vio_info, vmcs, guest_paddr, gpm, traps) {
        Ok(packet) => Ok(packet),
        Err(RvmError::NotFound) => {
            gpm.handle_page_fault(guest_paddr).map_err(|e| {
                warn!(
                    "[RVM] VM exit: Unhandled EPT violation @ {:#x}",
                    guest_paddr
                );
                e
            })?;
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

/// The common handler of VM exits.
///
/// Returns:
/// - `Ok(RvmExitPacket)` if need to forward the packet to the userspace handler.
/// - `Ok(None)` if the hypervisor has completed the exit handling and
///   can continue to run VMRESUME.
/// - `Err(RvmError)` if an error occurs.
pub fn vmexit_handler(
    vmcs: &mut AutoVmcs,
    guest_state: &mut GuestState,
    interrupt_state: &mut InterruptState,
    gpm: &Arc<dyn GuestPhysMemorySetTrait>,
    traps: &Mutex<TrapMap>,
) -> ExitResult {
    let exit_info = ExitInfo::from(vmcs);
    trace!("[RVM] VM exit: {:#x?}", exit_info);

    let res = match exit_info.exit_reason {
        ExitReason::EXTERNAL_INTERRUPT => handle_external_interrupt(vmcs, interrupt_state),
        ExitReason::INTERRUPT_WINDOW => handle_interrupt_window(vmcs),
        ExitReason::CPUID => handle_cpuid(&exit_info, vmcs, guest_state),
        ExitReason::HLT => handle_hlt(&exit_info, vmcs),
        ExitReason::VMCALL => handle_vmcall(&exit_info, vmcs, guest_state),
        ExitReason::CONTROL_REGISTER_ACCESS => {
            handle_cr_access(&exit_info, vmcs, guest_state, interrupt_state)
        }
        ExitReason::IO_INSTRUCTION => {
            handle_io_instruction(&exit_info, vmcs, guest_state, interrupt_state, traps)
        }
        ExitReason::PAUSE => handle_pause(&exit_info, vmcs),
        ExitReason::EPT_VIOLATION => handle_ept_violation(&exit_info, vmcs, gpm, traps),
        _ => Err(RvmError::NotSupported),
    };

    if res.is_err() {
        // FIXME: read via guest vaddr
        let mut buf = vec![0; exit_info.exit_instruction_length as usize];
        gpm.read_memory(vmcs.readXX(GUEST_CS_BASE) + exit_info.guest_rip, &mut buf)
            .expect("[RVM] read guest memory failed");
        warn!(
            "[RVM] VM exit handler for reason {:?} returned {:?}\n{}\nInstruction: {:02x?}",
            exit_info.exit_reason,
            res,
            guest_state.dump(vmcs),
            buf
        );
    }
    res
}
