//! The virtual CPU within a guest.

use super::{
    msr::*,
    structs::{MsrList, VmxPage},
    timer::PitTimer,
    vmcs::*,
    vmcs::{VmcsField16::*, VmcsField32::*, VmcsField64::*, VmcsFieldXX::*},
    vmexit::vmexit_handler,
    Guest,
};
use crate::interrupt::InterruptController;
use crate::{packet::RvmExitPacket, RvmError, RvmResult};
use alloc::{boxed::Box, sync::Arc};
use bit_field::BitField;
use core::fmt::{Debug, Formatter, Result};
use core::sync::atomic::{AtomicBool, Ordering};
use x86::{bits64::vmx, msr};
use x86_64::{
    registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags},
    registers::model_specific::{Efer, EferFlags},
};

/// Holds the register state used to restore a host.
#[repr(C)]
#[derive(Debug, Default)]
struct HostState {
    // Extended control registers.
    xcr0: u64,
    // Callee-save registers.
    rbx: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    // Processor flags.
    rflags: u64,
    // Return address.
    rip: u64,
}

/// Holds the register state used to restore a guest.
#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct GuestState {
    // Extended control registers.
    pub xcr0: u64,
    // Control registers.
    pub cr2: u64,
    //  RIP, RSP, and RFLAGS are automatically saved by VMX in the VMCS.
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

impl GuestState {
    pub fn dump(&self, vmcs: &AutoVmcs) -> alloc::string::String {
        format!(
            "VCPU Dump:\n\
            RIP: {:#x?}\n\
            RSP: {:#x?}\n\
            RFLAGS: {:#x?}\n\
            CR0: {:#x?}\n\
            CR3: {:#x?}\n\
            CR4: {:#x?}\n\
            {:#x?}",
            vmcs.readXX(GUEST_RIP),
            vmcs.readXX(GUEST_RSP),
            vmcs.readXX(GUEST_RFLAGS),
            Cr0Flags::from_bits_truncate(vmcs.readXX(GUEST_CR0) as u64),
            vmcs.readXX(GUEST_CR3),
            Cr4Flags::from_bits_truncate(vmcs.readXX(GUEST_CR4) as u64),
            self
        )
    }
}

/// Host and guest cpu register states.
#[repr(C)]
#[derive(Debug, Default)]
struct VmxState {
    host_rsp: u64,
    guest_state: GuestState,
    resume: bool,
}

/// Store the interruption state/virtual timer.
#[derive(Debug)]
pub struct InterruptState {
    pub timer: PitTimer,
    pub controller: InterruptController,
}

impl InterruptState {
    fn new() -> Self {
        Self {
            timer: PitTimer::new(),
            controller: InterruptController::new(u8::MAX as usize),
        }
    }

    /// Set timer IRQ pending if timeout.
    pub fn timer_irq(&mut self) {
        if self.timer.inner.enabled() && self.timer.inner.tick() {
            self.controller
                .virtual_interrupt(PitTimer::IRQ_NUM as usize);
        }
    }

    /// Injects an interrupt into the guest, if there is one pending.
    fn try_inject_interrupt(&mut self, vmcs: &mut AutoVmcs) -> RvmResult<()> {
        use super::consts::*;
        // Since hardware generated exceptions are delivered to the guest directly, the only exceptions
        // we see here are those we generate in the VMM, e.g. GP faults in vmexit handlers. Therefore
        // we simplify interrupt priority to 1) NMIs, 2) interrupts, and 3) generated exceptions. See
        // Volume 3, Section 6.9, Table 6-2.
        let vector = if self.controller.try_pop(NonMaskableInterrupt as usize) {
            NonMaskableInterrupt
        } else if let Some(vec) = self.controller.pop() {
            // Pop scans vectors from highest to lowest, which will correctly pop interrupts before
            // exceptions. All vectors <= VirtualizationException except the NMI vector are exceptions.
            vec as u8
        } else {
            return Ok(());
        };

        if vector > VirtualizationException && vector < IRQ0 {
            return Err(RvmError::NotSupported);
        } else {
            use InterruptibilityState as IntrState;
            let intr_state =
                IntrState::from_bits_truncate(vmcs.read32(GUEST_INTERRUPTIBILITY_STATE));
            let can_inject_nmi = !intr_state.contains(IntrState::BLOCKING_BY_NMI)
                && !intr_state.contains(IntrState::BLOCKING_BY_MOV_SS);
            let can_inject_external_int = vmcs.readXX(GUEST_RFLAGS).get_bit(9)
                && !intr_state.contains(IntrState::BLOCKING_BY_STI)
                && !intr_state.contains(IntrState::BLOCKING_BY_MOV_SS);
            if (vector >= IRQ0 && !can_inject_external_int)
                || (vector == NonMaskableInterrupt && !can_inject_nmi)
            {
                self.controller.virtual_interrupt(vector as usize);
                // If interrupts are disabled, we set VM exit on interrupt enable.
                vmcs.interrupt_window_exiting(true);
                return Ok(());
            }
        }

        // If the vector is non-maskable or interrupts are enabled, we inject an interrupt.
        vmcs.issue_interrupt(vector);

        // Volume 3, Section 6.9: Lower priority exceptions are discarded; lower priority interrupts are
        // held pending. Discarded exceptions are re-generated when the interrupt handler returns
        // execution to the point in the program or task where the exceptions and/or interrupts
        // occurred.
        self.controller
            .clear_and_keep(NonMaskableInterrupt as usize);

        Ok(())
    }
}

/// Represents a virtual CPU within a guest.
#[derive(Debug)]
pub struct Vcpu {
    vpid: u16,
    guest: Arc<Guest>,
    running: AtomicBool,
    vmx_state: VmxState,
    vmcs_page: VmxPage,
    host_msr_list: MsrList,
    guest_msr_list: MsrList,
    interrupt_state: InterruptState,
}

impl Vcpu {
    pub fn new(vpid: u16, guest: Arc<Guest>) -> RvmResult<Box<Self>> {
        // TODO pin thread
        assert_ne!(vpid, 0);
        let vmx_basic = VmxBasic::read();
        let host_msr_list = MsrList::new()?;
        let guest_msr_list = MsrList::new()?;
        let mut vmcs_page = VmxPage::alloc(0)?;
        vmcs_page.set_revision_id(vmx_basic.revision_id);

        let mut vcpu = Box::new(Self {
            vpid,
            guest,
            running: AtomicBool::new(false),
            vmx_state: VmxState::default(),
            vmcs_page,
            host_msr_list,
            guest_msr_list,
            interrupt_state: InterruptState::new(),
        });
        vcpu.init(0)?;
        Ok(vcpu)
    }

    pub fn init(&mut self, entry: u64) -> RvmResult {
        unsafe {
            vmx::vmclear(self.vmcs_page.phys_addr()).map_err(|_| RvmError::DeviceError)?;
            let mut vmcs = AutoVmcs::new(self.vmcs_page.phys_addr())?;
            self.setup_msr_list();
            self.init_vmcs_host(&mut vmcs)?;
            self.init_vmcs_control(&mut vmcs)?;
            self.init_vmcs_guest(&mut vmcs, entry)?;
        }
        Ok(())
    }

    /// Setup MSRs to be stored and loaded on VM exits/entrie.
    unsafe fn setup_msr_list(&mut self) {
        let msr_list = [
            msr::IA32_KERNEL_GSBASE,
            msr::IA32_STAR,
            msr::IA32_LSTAR,
            msr::IA32_FMASK,
            msr::IA32_TSC_ADJUST,
            msr::IA32_TSC_AUX,
        ];
        let count = msr_list.len();
        self.host_msr_list.set_count(count);
        self.guest_msr_list.set_count(count);
        for (i, &msr) in msr_list.iter().enumerate() {
            self.host_msr_list.edit_entry(i, msr, Msr::new(msr).read());
            self.guest_msr_list.edit_entry(i, msr, 0);
        }
    }

    /// Setup VMCS host state.
    unsafe fn init_vmcs_host(&self, vmcs: &mut AutoVmcs) -> RvmResult<()> {
        vmcs.write64(HOST_IA32_PAT, Msr::new(msr::IA32_PAT).read());
        vmcs.write64(HOST_IA32_EFER, Msr::new(msr::IA32_EFER).read());

        vmcs.writeXX(HOST_CR0, Cr0::read_raw() as usize);
        vmcs.writeXX(HOST_CR3, x86::controlregs::cr3() as usize);
        vmcs.writeXX(HOST_CR4, Cr4::read_raw() as usize);

        vmcs.write16(HOST_ES_SELECTOR, x86::segmentation::es().bits());
        vmcs.write16(HOST_CS_SELECTOR, x86::segmentation::cs().bits());
        vmcs.write16(HOST_SS_SELECTOR, x86::segmentation::ss().bits());
        vmcs.write16(HOST_DS_SELECTOR, x86::segmentation::ds().bits());
        vmcs.write16(HOST_FS_SELECTOR, x86::segmentation::fs().bits());
        vmcs.write16(HOST_GS_SELECTOR, x86::segmentation::gs().bits());
        let tr = x86::task::tr().bits() & 0xf8;
        assert_ne!(tr, 0, "TR must not be 0");
        vmcs.write16(HOST_TR_SELECTOR, tr);

        vmcs.writeXX(HOST_FS_BASE, Msr::new(msr::IA32_FS_BASE).read() as usize);
        vmcs.writeXX(HOST_GS_BASE, Msr::new(msr::IA32_GS_BASE).read() as usize);
        vmcs.writeXX(HOST_TR_BASE, tr_base(tr) as usize);

        let mut dtp = x86::dtables::DescriptorTablePointer::new(&0u64);
        llvm_asm!("sgdt ($0)" :: "r"(&mut dtp) : "memory" : "volatile");
        vmcs.writeXX(HOST_GDTR_BASE, dtp.base as usize);
        llvm_asm!("sidt ($0)" :: "r"(&mut dtp) : "memory" : "volatile");
        vmcs.writeXX(HOST_IDTR_BASE, dtp.base as usize);

        vmcs.writeXX(HOST_IA32_SYSENTER_ESP, 0);
        vmcs.writeXX(HOST_IA32_SYSENTER_EIP, 0);
        vmcs.write32(HOST_IA32_SYSENTER_CS, 0);

        vmcs.writeXX(HOST_RSP, &self.vmx_state as *const _ as usize);
        vmcs.writeXX(HOST_RIP, vmx_exit as usize);
        Ok(())
    }

    /// Setup VMCS guest state.
    unsafe fn init_vmcs_guest(&self, vmcs: &mut AutoVmcs, entry: u64) -> RvmResult<()> {
        vmcs.write64(GUEST_IA32_PAT, Msr::new(msr::IA32_PAT).read());
        let mut efer = Efer::read();
        efer.remove(EferFlags::LONG_MODE_ENABLE | EferFlags::LONG_MODE_ACTIVE);
        vmcs.write64(GUEST_IA32_EFER, efer.bits());

        vmcs.writeXX(GUEST_CR3, 0);
        let cr0 = Cr0Flags::NUMERIC_ERROR.bits() as usize;
        vmcs.writeXX(GUEST_CR0, cr0);
        // Ensure that CR0.NE remains set by masking and manually handling writes to CR0 that unset it.
        vmcs.writeXX(CR0_GUEST_HOST_MASK, cr0);
        vmcs.writeXX(CR0_READ_SHADOW, cr0);
        let cr4 = Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS.bits() as usize;
        vmcs.writeXX(GUEST_CR4, cr4);
        // For now, the guest can own all of the CR4 bits except VMXE, which it shouldn't touch.
        vmcs.writeXX(CR4_GUEST_HOST_MASK, cr4);
        vmcs.writeXX(CR4_READ_SHADOW, 0);

        let default_rights = GuestRegisterAccessRights::default().bits();
        let cs_rights = default_rights | GuestRegisterAccessRights::EXECUTABLE.bits();

        // Setup CS and entry point.
        vmcs.write32(GUEST_CS_LIMIT, 0xffff);
        vmcs.write32(GUEST_CS_AR_BYTES, cs_rights);
        if entry > 0 {
            vmcs.write16(GUEST_CS_SELECTOR, 0);
            vmcs.writeXX(GUEST_CS_BASE, 0);
            vmcs.writeXX(GUEST_RIP, entry as usize);
        } else {
            // Reference: Volume 3, Section 9.1.4, First Instruction Executed.
            vmcs.write16(GUEST_CS_SELECTOR, 0xf000);
            vmcs.writeXX(GUEST_CS_BASE, 0xffff_0000);
            vmcs.writeXX(GUEST_RIP, 0xfff0);
        }

        // Setup DS, SS, ES, FS, GS, TR, LDTR, GDTR, IDTR.
        vmcs.write16(GUEST_DS_SELECTOR, 0);
        vmcs.writeXX(GUEST_DS_BASE, 0);
        vmcs.write32(GUEST_DS_LIMIT, 0xffff);
        vmcs.write32(GUEST_DS_AR_BYTES, default_rights);
        vmcs.write16(GUEST_SS_SELECTOR, 0);
        vmcs.writeXX(GUEST_SS_BASE, 0);
        vmcs.write32(GUEST_SS_LIMIT, 0xffff);
        vmcs.write32(GUEST_SS_AR_BYTES, default_rights);
        vmcs.write16(GUEST_ES_SELECTOR, 0);
        vmcs.writeXX(GUEST_ES_BASE, 0);
        vmcs.write32(GUEST_ES_LIMIT, 0xffff);
        vmcs.write32(GUEST_ES_AR_BYTES, default_rights);
        vmcs.write16(GUEST_FS_SELECTOR, 0);
        vmcs.writeXX(GUEST_FS_BASE, 0);
        vmcs.write32(GUEST_FS_LIMIT, 0xffff);
        vmcs.write32(GUEST_FS_AR_BYTES, default_rights);
        vmcs.write16(GUEST_GS_SELECTOR, 0);
        vmcs.writeXX(GUEST_GS_BASE, 0);
        vmcs.write32(GUEST_GS_LIMIT, 0xffff);
        vmcs.write32(GUEST_GS_AR_BYTES, default_rights);
        vmcs.write16(GUEST_TR_SELECTOR, 0);
        vmcs.writeXX(GUEST_TR_BASE, 0);
        vmcs.write32(GUEST_TR_LIMIT, 0xffff);
        vmcs.write32(
            GUEST_TR_AR_BYTES,
            (GuestRegisterAccessRights::TSS_BUSY | GuestRegisterAccessRights::PRESENT).bits(),
        );
        vmcs.write16(GUEST_LDTR_SELECTOR, 0);
        vmcs.writeXX(GUEST_LDTR_BASE, 0);
        vmcs.write32(GUEST_LDTR_LIMIT, 0xffff);
        vmcs.write32(
            GUEST_LDTR_AR_BYTES,
            (GuestRegisterAccessRights::WRITABLE | GuestRegisterAccessRights::PRESENT).bits(),
        );
        vmcs.writeXX(GUEST_GDTR_BASE, 0);
        vmcs.write32(GUEST_GDTR_LIMIT, 0xffff);
        vmcs.writeXX(GUEST_IDTR_BASE, 0);
        vmcs.write32(GUEST_IDTR_LIMIT, 0xffff);

        vmcs.writeXX(GUEST_RSP, 0);
        // Set all reserved RFLAGS bits to their correct values
        vmcs.writeXX(GUEST_RFLAGS, 0x2);

        vmcs.write32(GUEST_INTERRUPTIBILITY_STATE, 0);
        vmcs.write32(GUEST_ACTIVITY_STATE, 0);
        vmcs.writeXX(GUEST_PENDING_DBG_EXCEPTIONS, 0);

        // From Volume 3, Section 26.3.1.1: The IA32_SYSENTER_ESP field and the
        // IA32_SYSENTER_EIP field must each contain a canonical address.
        vmcs.writeXX(GUEST_IA32_SYSENTER_ESP, 0);
        vmcs.writeXX(GUEST_IA32_SYSENTER_EIP, 0);
        vmcs.write32(GUEST_IA32_SYSENTER_CS, 0);

        // From Volume 3, Section 24.4.2: If the “VMCS shadowing” VM-execution
        // control is 1, the VMREAD and VMWRITE instructions access the VMCS
        // referenced by this pointer (see Section 24.10). Otherwise, software
        // should set this field to FFFFFFFF_FFFFFFFFH to avoid VM-entry
        // failures (see Section 26.3.1.5).
        vmcs.write64(VMCS_LINK_POINTER, u64::MAX);

        Ok(())
    }

    /// Setup VMCS control fields.
    unsafe fn init_vmcs_control(&self, vmcs: &mut AutoVmcs) -> RvmResult<()> {
        use CpuBasedVmExecControls as CpuCtrl;
        use PinBasedVmExecControls as PinCtrl;
        use SecondaryCpuBasedVmExecControls as CpuCtrl2;

        // Setup secondary processor-based VMCS controls.
        vmcs.set_control(
            SECONDARY_VM_EXEC_CONTROL,
            Msr::new(msr::IA32_VMX_PROCBASED_CTLS2).read(),
            0,
            (CpuCtrl2::EPT
                | CpuCtrl2::RDTSCP
                | CpuCtrl2::VIRTUAL_X2APIC
                | CpuCtrl2::VPID
                | CpuCtrl2::UNRESTRICTED_GUEST)
                .bits(),
            0,
        )?;
        // Enable use of INVPCID instruction if available.
        vmcs.set_control(
            SECONDARY_VM_EXEC_CONTROL,
            Msr::new(msr::IA32_VMX_PROCBASED_CTLS2).read(),
            vmcs.read32(SECONDARY_VM_EXEC_CONTROL) as u64,
            CpuCtrl2::INVPCID.bits(),
            0,
        )
        .ok();

        // Setup pin-based VMCS controls.
        vmcs.set_control(
            PIN_BASED_VM_EXEC_CONTROL,
            Msr::new(msr::IA32_VMX_TRUE_PINBASED_CTLS).read(),
            Msr::new(msr::IA32_VMX_PINBASED_CTLS).read(),
            (PinCtrl::INTR_EXITING | PinCtrl::NMI_EXITING).bits(),
            0,
        )?;

        // Setup primary processor-based VMCS controls.
        vmcs.set_control(
            CPU_BASED_VM_EXEC_CONTROL,
            Msr::new(msr::IA32_VMX_TRUE_PROCBASED_CTLS).read(),
            Msr::new(msr::IA32_VMX_PROCBASED_CTLS).read(),
            // Enable XXX
            (CpuCtrl::INTR_WINDOW_EXITING
                | CpuCtrl::HLT_EXITING
                | CpuCtrl::VIRTUAL_TPR
                | CpuCtrl::UNCOND_IO_EXITING
                | CpuCtrl::USE_MSR_BITMAPS
                | CpuCtrl::PAUSE_EXITING
                | CpuCtrl::SEC_CONTROLS)
                .bits(),
            // Disable XXX
            (CpuCtrl::CR3_LOAD_EXITING
                | CpuCtrl::CR3_STORE_EXITING
                | CpuCtrl::CR8_LOAD_EXITING
                | CpuCtrl::CR8_STORE_EXITING)
                .bits(),
        )?;
        // We only enable interrupt-window exiting above to ensure that the
        // processor supports it for later use. So disable it for now.
        vmcs.interrupt_window_exiting(false);

        // Setup VM-exit VMCS controls.
        vmcs.set_control(
            VM_EXIT_CONTROLS,
            Msr::new(msr::IA32_VMX_TRUE_EXIT_CTLS).read(),
            Msr::new(msr::IA32_VMX_EXIT_CTLS).read(),
            (VmExitControls::HOST_ADDR_SPACE_SIZE
                | VmExitControls::SAVE_IA32_PAT
                | VmExitControls::LOAD_IA32_PAT
                | VmExitControls::SAVE_IA32_EFER
                | VmExitControls::LOAD_IA32_EFER
                | VmExitControls::ACK_INTR_ON_EXIT)
                .bits(),
            0,
        )?;

        // Setup VM-entry VMCS controls.
        vmcs.set_control(
            VM_ENTRY_CONTROLS,
            Msr::new(msr::IA32_VMX_TRUE_ENTRY_CTLS).read(),
            Msr::new(msr::IA32_VMX_ENTRY_CTLS).read(),
            (VmEntryControls::LOAD_IA32_PAT | VmEntryControls::LOAD_IA32_EFER).bits(),
            0,
        )?;

        // From Volume 3, Section 24.6.3: The exception bitmap is a 32-bit field
        // that contains one bit for each exception. When an exception occurs,
        // its vector is used to select a bit in this field. If the bit is 1,
        // the exception causes a VM exit. If the bit is 0, the exception is
        // delivered normally through the IDT, using the descriptor
        // corresponding to the exception’s vector.
        //
        // From Volume 3, Section 25.2: If software desires VM exits on all page
        // faults, it can set bit 14 in the exception bitmap to 1 and set the
        // page-fault error-code mask and match fields each to 00000000H.
        vmcs.write32(EXCEPTION_BITMAP, 0);
        vmcs.write32(PAGE_FAULT_ERROR_CODE_MASK, 0);
        vmcs.write32(PAGE_FAULT_ERROR_CODE_MATCH, 0);

        // From Volume 3, Section 28.1: Virtual-processor identifiers (VPIDs)
        // introduce to VMX operation a facility by which a logical processor may
        // cache information for multiple linear-address spaces. When VPIDs are
        // used, VMX transitions may retain cached information and the logical
        // processor switches to a different linear-address space.
        //
        // From Volume 3, Section 26.2.1.1: If the “enable VPID” VM-execution
        // control is 1, the value of the VPID VM-execution control field must not
        // be 0000H.
        //
        // From Volume 3, Section 28.3.3.3: If EPT is in use, the logical processor
        // associates all mappings it creates with the value of bits 51:12 of
        // current EPTP. If a VMM uses different EPTP values for different guests,
        // it may use the same VPID for those guests.
        //
        // From Volume 3, Section 28.3.3.1: Operations that architecturally
        // invalidate entries in the TLBs or paging-structure caches independent of
        // VMX operation (e.g., the INVLPG and INVPCID instructions) invalidate
        // linear mappings and combined mappings. They are required to do so only
        // for the current VPID (but, for combined mappings, all EP4TAs). Linear
        // mappings for the current VPID are invalidated even if EPT is in use.
        // Combined mappings for the current VPID are invalidated even if EPT is
        // not in use.
        vmcs.write16(VIRTUAL_PROCESSOR_ID, self.vpid);

        // From Volume 3, Section 28.2: The extended page-table mechanism (EPT) is a
        // feature that can be used to support the virtualization of physical
        // memory. When EPT is in use, certain addresses that would normally be
        // treated as physical addresses (and used to access memory) are instead
        // treated as guest-physical addresses. Guest-physical addresses are
        // translated by traversing a set of EPT paging structures to produce
        // physical addresses that are used to access memory.
        let eptp = self.guest.extended_page_table_pointer() as u64;
        vmcs.write64(EPT_POINTER, eptp);

        // From Volume 3, Section 28.3.3.4: Software can use an INVEPT with type all
        // ALL_CONTEXT to prevent undesired retention of cached EPT information. Here,
        // we only care about invalidating information associated with this EPTP.
        invept(InvEptType::SingleContext, eptp);

        // Setup MSR handling.
        vmcs.write64(MSR_BITMAP, 0); // TODO: msr_bitmap_addr

        vmcs.write64(VM_EXIT_MSR_LOAD_ADDR, self.host_msr_list.paddr());
        vmcs.write32(VM_EXIT_MSR_LOAD_COUNT, self.host_msr_list.count());
        vmcs.write64(VM_EXIT_MSR_STORE_ADDR, self.guest_msr_list.paddr());
        vmcs.write32(VM_EXIT_MSR_STORE_COUNT, self.guest_msr_list.count());
        vmcs.write64(VM_ENTRY_MSR_LOAD_ADDR, self.guest_msr_list.paddr());
        vmcs.write32(VM_ENTRY_MSR_LOAD_COUNT, self.guest_msr_list.count());

        Ok(())
    }

    pub fn resume(&mut self) -> RvmResult<RvmExitPacket> {
        loop {
            let mut vmcs = AutoVmcs::new(self.vmcs_page.phys_addr())?;

            self.interrupt_state.try_inject_interrupt(&mut vmcs)?;
            // TODO: save/restore guest extended registers (x87/SSE)

            // VM Entry
            self.running.store(true, Ordering::SeqCst);
            trace!("[RVM] vmx entry");
            let res = unsafe { vmx_entry(&mut self.vmx_state) };
            trace!("[RVM] vmx exit");
            self.running.store(false, Ordering::SeqCst);

            res.map_err(|err| {
                warn!(
                    "[RVM] VCPU resume failed: {:?}",
                    VmInstructionError::from(vmcs.read32(VM_INSTRUCTION_ERROR))
                );
                err
            })?;

            // VM Exit
            self.vmx_state.resume = true;
            match vmexit_handler(
                &mut vmcs,
                &mut self.vmx_state.guest_state,
                &mut self.interrupt_state,
                &self.guest.traps,
            )? {
                Some(packet) => return Ok(packet), // forward to user mode handler
                None => continue,
            }
        }
    }

    pub fn write_state(&mut self, guest_state: &GuestState) -> RvmResult<()> {
        self.vmx_state.guest_state = guest_state.clone();
        Ok(())
    }

    pub fn read_state(&self) -> RvmResult<GuestState> {
        Ok(self.vmx_state.guest_state.clone())
    }

    /// Inject a virtual interrupt.
    pub fn virtual_interrupt(&mut self, vector: u32) -> RvmResult<()> {
        self.interrupt_state
            .controller
            .virtual_interrupt(vector as usize);
        Ok(())
    }
}

impl Drop for Vcpu {
    fn drop(&mut self) {
        info!("Vcpu free {:#x?}", self);
        // TODO pin thread
        unsafe { vmx::vmclear(self.vmcs_page.phys_addr()).unwrap() };
    }
}

#[naked]
#[inline(never)]
unsafe extern "sysv64" fn vmx_entry(_vmx_state: &mut VmxState) -> RvmResult<()> {
    llvm_asm!("
    // Store host callee save registers, return address, and processor flags.
    pushf
    push    r15
    push    r14
    push    r13
    push    r12
    push    rbp
    push    rbx

    // Store RSP and switch to GuestState
    mov     [rdi], rsp
    mov     rsp, rdi

    // Load the guest registers not covered by the VMCS.
    add     rsp, 16      // skip xcr0
    pop     rax
    mov     cr2, rax
    pop     rax
    pop     rbx
    pop     rcx
    pop     rdx
    pop     rbp
    pop     rsi
    pop     rdi
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15

    // Check if vmlaunch or vmresume is needed
    cmp     byte ptr [rsp], 0
    jne     1f
    vmlaunch
    jmp     2f
1:  vmresume
2:
    // We will only be here if vmlaunch or vmresume failed.
    // Restore host callee, RSP and return address.
    mov     rsp, [rsp - 18*8]
    pop     rbx
    pop     rbp
    pop     r12
    pop     r13
    pop     r14
    pop     r15
    popf
"
    :
    :
    : "cc", "memory",
      "rax", "rbx", "rcx", "rdx", "rdi", "rsi"
      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    : "intel", "volatile");

    // We will only be here if vmlaunch or vmresume failed.
    Err(RvmError::DeviceError)
}

/// This is effectively the second-half of vmx_entry. When we return from a
/// VM exit, vmx_state argument is stored in RSP. We use this to restore the
/// stack and registers to the state they were in when vmx_entry was called.
#[naked]
#[inline(never)]
unsafe extern "sysv64" fn vmx_exit(_vmx_state: &mut VmxState) -> RvmResult<()> {
    llvm_asm!("
    // Store the guest registers not covered by the VMCS. At this point,
    // vmx_state is in RSP.
    push    r15
    push    r14
    push    r13
    push    r12
    push    r11
    push    r10
    push    r9
    push    r8
    push    rdi
    push    rsi
    push    rbp
    push    rdx
    push    rcx
    push    rbx
    push    rax
    mov     rax, cr2
    push    rax
    sub     rsp, 16      // skip xcr0

    pop     rsp

    // Load host callee save registers, return address, and processor flags.
    pop     rbx
    pop     rbp
    pop     r12
    pop     r13
    pop     r14
    pop     r15
    popf
"
    :
    : 
    : "cc", "memory",
      "rax", "rbx", "rcx", "rdx", "rdi", "rsi"
      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    : "intel", "volatile");

    Ok(())
}

#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct InvEptDescriptor {
    /// EPT pointer (EPTP)
    eptp: u64,
    reserved: u64,
}

#[derive(Debug)]
#[repr(u64)]
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

struct VmInstructionError {
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

/// Get TR base.
unsafe fn tr_base(tr: u16) -> u64 {
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
