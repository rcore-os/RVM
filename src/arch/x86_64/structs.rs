//! Some global structs used for VMX.

use alloc::vec::Vec;
use spin::Mutex;
use x86_64::registers::control::{Cr0, Cr4, Cr4Flags};
use x86_64::{instructions::vmx, PhysAddr};

use rcore_memory::PAGE_SIZE;

use super::msr::*;
use crate::memory::{alloc_frame, dealloc_frame, phys_to_virt};
use crate::rvm::{RvmError, RvmResult};

use super::feature::x86_feature_init;

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
            Err(RvmError::NoDeviceSpace)
        }
    }

    /// Initialize the version identifier (first 4 bytes) for VMXON region and
    /// VMCS region.
    pub fn set_revision_id(&mut self, revision_id: u32) {
        let revision_id = revision_id & 0x7fff_ffff;
        unsafe { *self.as_ptr::<u32>() = revision_id };
    }

    pub fn phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.paddr as u64)
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
        println!("VmxPage free {:#x?}", self);
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

/// Global VMX states used for all guests.
#[derive(Default)]
pub struct VmmState {
    num_guests: usize,
    vmxon_pages: Vec<VmxPage>,
}

lazy_static! {
    pub static ref VMM_STATE: Mutex<VmmState> = Mutex::new(VmmState::default());
}

impl VmmState {
    pub fn alloc(&mut self) -> RvmResult<()> {
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

    fn vmxon_task(&mut self, cpu_num: usize) -> RvmResult<()> {
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
        if !cr_is_valid(cr0.bits(), MSR_IA32_VMX_CR0_FIXED0, MSR_IA32_VMX_CR0_FIXED1) {
            return Err(RvmError::DeviceError);
        }
        let cr4 = Cr4::read() | Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS;
        if !cr_is_valid(cr4.bits(), MSR_IA32_VMX_CR4_FIXED0, MSR_IA32_VMX_CR4_FIXED1) {
            return Err(RvmError::DeviceError);
        }

        // Setup VMXON page.
        page.set_revision_id(vmx_basic.revision_id);

        unsafe {
            // Enable VMX using the VMXE bit.
            Cr4::write(cr4);

            // Execute VMXON.
            if vmx::vmxon(page.phys_addr()).is_none() {
                warn!("[RVM] failed to turn on VMX on CPU {}", cpu_num);
                return Err(RvmError::DeviceError);
            }
            info!("[RVM] successed to turn on VMX on CPU {}", cpu_num);
        }

        x86_feature_init();

        Ok(())
    }

    fn vmxoff_task(&self) {
        unsafe {
            // Execute VMXOFF.
            if vmx::vmxoff().is_none() {
                warn!(
                    "[RVM] failed to turn off VMX on CPU {}",
                    crate::arch::cpu::id()
                );
                return;
            }
            // Disable VMX.
            Cr4::update(|cr4| cr4.remove(Cr4Flags::VIRTUAL_MACHINE_EXTENSIONS));
        }
    }
}

/// Check whether the CR0/CR0 has required fixed bits.
fn cr_is_valid(cr_value: u64, fixed0_msr: u32, fixed1_msr: u32) -> bool {
    let fixed0 = unsafe { Msr::new(fixed0_msr).read() };
    let fixed1 = unsafe { Msr::new(fixed1_msr).read() };
    return ((cr_value & fixed1) | fixed0) == cr_value;
}
