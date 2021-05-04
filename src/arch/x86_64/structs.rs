//! Some structures used for VMX.

use alloc::vec::Vec;
use core::fmt::{Debug, Formatter, Result};
use lazy_static::lazy_static;
use numeric_enum_macro::numeric_enum;
use spin::Mutex;
use x86::bits64::vmx;
use x86_64::registers::control::{Cr0, Cr4, Cr4Flags};

use super::msr::*;
use super::utils::{cr0_is_valid, cr4_is_valid};
use crate::ffi::{alloc_frame, dealloc_frame, phys_to_virt};
use crate::{RvmError, RvmResult, PAGE_SIZE};

/// A physical frame (or virtual page) of size PAGE_SIZE used as VMXON region,
/// VMCS region, or MSR page, etc.
#[derive(Debug)]
pub struct VmxPage {
    paddr: usize,
}

impl VmxPage {
    pub fn alloc(fill: u8) -> RvmResult<Self> {
        if let Some(paddr) = alloc_frame() {
            let page = Self { paddr };
            unsafe { core::ptr::write_bytes(page.vaddr() as *mut u8, fill, PAGE_SIZE) };
            Ok(page)
        } else {
            Err(RvmError::NoMemory)
        }
    }

    /// Initialize the version identifier (first 4 bytes) for VMXON region and
    /// VMCS region.
    pub fn set_revision_id(&mut self, revision_id: u32) {
        let revision_id = revision_id & 0x7fff_ffff;
        unsafe { *self.as_ptr::<u32>() = revision_id };
    }

    pub fn phys_addr(&self) -> u64 {
        self.paddr as u64
    }

    pub fn as_ptr<T>(&self) -> *mut T {
        self.vaddr() as *mut T
    }

    fn vaddr(&self) -> usize {
        phys_to_virt(self.paddr)
    }
}

impl Drop for VmxPage {
    fn drop(&mut self) {
        debug!("VmxPage free {:#x?}", self);
        dealloc_frame(self.paddr);
    }
}

#[repr(C, packed)]
pub struct MsrListEntry {
    msr_index: u32,
    _reserved: u32,
    msr_value: u64,
}

#[derive(Debug)]
pub struct MsrList {
    page: VmxPage,
    count: usize,
}

impl MsrList {
    pub fn new() -> RvmResult<Self> {
        Ok(Self {
            page: VmxPage::alloc(0)?,
            count: 0,
        })
    }

    pub fn set_count(&mut self, count: usize) {
        // From Volume 3, Appendix A.6: Specifically, if the value bits 27:25 of
        // IA32_VMX_MISC is N, then 512 * (N + 1) is the recommended maximum number
        // of MSRs to be included in each list.
        //
        // From Volume 3, Section 24.7.2: This field specifies the number of MSRs to
        // be stored on VM exit. It is recommended that this count not exceed 512
        // bytes.
        //
        // Since these two statements conflict, we are taking the conservative
        // minimum and asserting that: index < (512 bytes / size of MsrListEntry).
        assert!(count < 512 / core::mem::size_of::<MsrListEntry>());
        self.count = count;
    }

    pub fn count(&self) -> u32 {
        self.count as u32
    }

    pub fn paddr(&self) -> u64 {
        self.page.paddr as u64
    }

    pub unsafe fn edit_entry(&mut self, index: usize, msr_index: u32, msr_value: u64) {
        // From Volume 3, Section 24.7.2.
        assert!(index < self.count);
        let entry = &mut *self.page.as_ptr::<MsrListEntry>().add(index);
        entry.msr_index = msr_index;
        entry.msr_value = msr_value;
    }
}

#[derive(Debug)]
pub struct MsrBitmaps {
    page: VmxPage,
}

impl MsrBitmaps {
    pub fn new() -> RvmResult<Self> {
        Ok(Self {
            page: VmxPage::alloc(u8::MAX)?,
        })
    }

    pub fn paddr(&self) -> u64 {
        self.page.paddr as u64
    }

    pub unsafe fn ignore(&mut self, msr: u32, ignore_writes: bool) {
        // From Volume 3, Section 24.6.9.
        let mut ptr = self.page.as_ptr::<u8>();
        if msr >= 0xc000_0000 {
            ptr = ptr.add(1 << 10);
        }
        let msr_low = msr & 0x1fff;
        let msr_byte = (msr_low / 8) as usize;
        let msr_bit = (msr_low % 8) as u8;

        // Ignore reads to the MSR.
        core::slice::from_raw_parts_mut(ptr, 1024)[msr_byte] &= !(1 << msr_bit);

        if ignore_writes {
            // Ignore writes to the MSR.
            core::slice::from_raw_parts_mut(ptr.add(2 << 10), 1024)[msr_byte] &= !(1 << msr_bit);
        }
    }
}

/// Global VMX states used for all guests.
#[derive(Default)]
pub struct VmmGlobalState {
    num_guests: usize,
    vmxon_pages: Vec<VmxPage>,
}

lazy_static! {
    pub static ref VMM_GLOBAL_STATE: Mutex<VmmGlobalState> = Mutex::new(VmmGlobalState::default());
}

impl VmmGlobalState {
    pub fn alloc(&mut self) -> RvmResult {
        if !super::check_hypervisor_feature() {
            return Err(RvmError::NotSupported);
        }

        let cpu_id = raw_cpuid::CpuId::new()
            .get_feature_info()
            .unwrap()
            .initial_local_apic_id();
        if cpu_id != 0 {
            warn!("[RVM] multiprocessor is unsupported");
            return Err(RvmError::NotSupported);
        }

        if self.num_guests == 0 {
            // TODO: support multiple cpu
            let num_cpus = 1;
            self.vmxon_pages = Vec::with_capacity(num_cpus);
            for _ in 0..num_cpus {
                self.vmxon_pages.push(VmxPage::alloc(0)?);
            }

            // Enable VMX for all online CPUs.
            // TODO: run on each cpu
            for i in 0..num_cpus {
                if let Err(e) = self.vmxon_task(i) {
                    self.vmxoff_task();
                    return Err(e);
                }
            }
        }
        self.num_guests += 1;
        Ok(())
    }

    pub fn free(&mut self) {
        self.num_guests -= 1;
        if self.num_guests == 0 {
            let num_cpus = 1;
            for _ in 0..num_cpus {
                self.vmxoff_task();
            }
            self.vmxon_pages.clear();
        }
    }

    fn vmxon_task(&mut self, cpu_num: usize) -> RvmResult {
        let mut cr4 = Cr4::read();
        if cr4.contains(Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS) {
            warn!("[RVM] VMX is already turned on");
            return Err(RvmError::BadState);
        }

        let page = &mut self.vmxon_pages[cpu_num];
        let vmx_basic = VmxBasic::read();

        // It is a value greater than 0 and at most 4096 (bit 44 is set if and
        // only if bits 43:32 are clear).
        if vmx_basic.region_size as usize > PAGE_SIZE {
            return Err(RvmError::NotSupported);
        }
        // Check use of write-back memory for VMX regions is supported.
        if !vmx_basic.write_back {
            return Err(RvmError::NotSupported);
        }
        // Check that we have instruction information when we VM exit on IO.
        if !vmx_basic.io_exit_info {
            return Err(RvmError::NotSupported);
        }
        // Check that full VMX controls are supported.
        if !vmx_basic.vmx_flex_controls {
            return Err(RvmError::NotSupported);
        }

        // TODO: check EPT

        // Enable VMXON, if required.
        let ctrl = FeatureControl::read();
        let locked = ctrl.contains(FeatureControlFlags::LOCKED);
        let vmxon_outside = ctrl.contains(FeatureControlFlags::VMXON_ENABLED_OUTSIDE_SMX);
        if !locked {
            unsafe {
                FeatureControl::write(
                    ctrl | FeatureControlFlags::LOCKED
                        | FeatureControlFlags::VMXON_ENABLED_OUTSIDE_SMX,
                )
            };
        } else if !vmxon_outside {
            warn!("[RVM] disabled by BIOS");
            return Err(RvmError::NotSupported);
        }

        // Check control registers are in a VMX-friendly state.
        let cr0 = Cr0::read();
        if !cr0_is_valid(cr0.bits(), false) {
            return Err(RvmError::BadState);
        }
        cr4 |= Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS;
        if !cr4_is_valid(cr4.bits()) {
            return Err(RvmError::BadState);
        }

        // Setup VMXON page.
        page.set_revision_id(vmx_basic.revision_id);

        unsafe {
            // Enable VMX using the VMXE bit.
            Cr4::write(cr4);

            // Execute VMXON.
            if vmx::vmxon(page.phys_addr()).is_err() {
                warn!("[RVM] failed to turn on VMX on CPU {}", cpu_num);
                return Err(RvmError::Internal);
            }
            info!("[RVM] successed to turn on VMX on CPU {}", cpu_num);
        }

        Ok(())
    }

    fn vmxoff_task(&self) {
        unsafe {
            // Execute VMXOFF.
            if vmx::vmxoff().is_err() {
                warn!("[RVM] failed to turn off VMX");
                return;
            }
            // Disable VMX.
            Cr4::update(|cr4| cr4.remove(Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS));
            info!("[RVM] successed to turn off VMX");
        }
    }
}

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
