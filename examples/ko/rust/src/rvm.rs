use alloc::{boxed::Box, sync::Arc, vec::Vec};
use spin::Mutex;

use rvm::{DefaultGuestPhysMemorySet, Guest, GuestMemoryAttr, RvmError, RvmPageTable, Vcpu};

use crate::error::{retval, KernelError, KernelResult};
use crate::ffi::ctypes::*;

impl From<RvmError> for KernelError {
    fn from(err: RvmError) -> Self {
        match err {
            RvmError::Internal => Self::EIO,
            RvmError::NotSupported => Self::ENOSYS,
            RvmError::NoMemory => Self::ENOMEM,
            RvmError::InvalidParam => Self::EINVAL,
            RvmError::OutOfRange => Self::EFAULT,
            RvmError::BadState => Self::EBUSY,
            RvmError::NotFound => Self::EINVAL,
        }
    }
}

const MAX_VCPU_NUM_PER_FILE: usize = 32;

#[repr(C)]
#[derive(Debug)]
struct RvmDev {
    guest: Option<Arc<Guest>>,
    gpm: Option<Arc<DefaultGuestPhysMemorySet>>,
    vcpus: Vec<Mutex<Vcpu>>,
}

impl RvmDev {
    unsafe fn from_raw(ptr: *mut c_void) -> &'static Self {
        &*(ptr as *const Self)
    }

    unsafe fn from_raw_mut(ptr: *mut c_void) -> &'static mut Self {
        &mut *(ptr as *mut Self)
    }

    fn new() -> Self {
        info!("NEW");
        Self {
            guest: None,
            gpm: None,
            vcpus: Vec::new(),
        }
    }

    fn guest_create(&mut self) -> KernelResult {
        if self.guest.is_some() {
            warn!("[RVM] guest exists");
            return Err(KernelError::EBUSY);
        }
        let gpm = DefaultGuestPhysMemorySet::new();
        self.guest = Some(Guest::new(gpm.clone())?);
        self.gpm = Some(gpm.clone());
        Ok(0)
    }

    fn guest_add_memory_region(&self, gpaddr: usize, size: usize) -> KernelResult {
        if let Some(guest) = &self.guest {
            guest.add_memory_region(gpaddr, size, None)?;
            Ok(0)
        } else {
            warn!("[RVM] guest is not created");
            Err(KernelError::EINVAL)
        }
    }

    fn vcpu_create(&mut self, entry: u64) -> KernelResult {
        if let Some(guest) = &self.guest {
            let vcpu_id = self.vcpus.len() + 1;
            if vcpu_id > MAX_VCPU_NUM_PER_FILE {
                warn!(
                    "[RVM] too many vcpus (maximum is {})",
                    MAX_VCPU_NUM_PER_FILE
                );
                return Err(KernelError::ENOMEM);
            }
            let vcpu = Mutex::new(Vcpu::new(entry, guest.clone())?);
            self.vcpus.push(vcpu);
            Ok(vcpu_id)
        } else {
            warn!("[RVM] guest is not created");
            Err(KernelError::EINVAL)
        }
    }

    fn gpa_to_hpa(&self, gpaddr: usize, alloc: bool) -> KernelResult {
        if let Some(gpm) = &self.gpm {
            let mut rvm_pt = gpm.rvm_page_table.lock();
            let mut target = rvm_pt.query(gpaddr).unwrap_or(0);
            if target == 0 && alloc {
                target =
                    unsafe { rvm_extern_fn::rvm_alloc_frame() }.expect("failed to alloc frame");
                rvm_pt
                    .map(gpaddr, target, GuestMemoryAttr::default())
                    .expect("failed to create GPA -> HPA mapping");
            }
            Ok(target)
        } else {
            warn!("[RVM] guest is not created");
            Err(KernelError::EINVAL)
        }
    }
}

impl Drop for RvmDev {
    fn drop(&mut self) {
        info!("DROP");
    }
}

#[no_mangle]
unsafe extern "C" fn check_hypervisor_feature() -> bool {
    rvm::check_hypervisor_feature()
}

#[no_mangle]
unsafe extern "C" fn new_rvm_dev() -> *mut c_void {
    Box::into_raw(Box::new(RvmDev::new())) as *mut c_void
}

#[no_mangle]
unsafe extern "C" fn free_rvm_dev(rvm_dev: *mut c_void) {
    drop(Box::from_raw(rvm_dev as *mut RvmDev));
}

#[no_mangle]
unsafe extern "C" fn rvm_guest_create(rvm_dev: *mut c_void) -> c_int {
    let dev = RvmDev::from_raw_mut(rvm_dev);
    retval(dev.guest_create())
}

#[no_mangle]
unsafe extern "C" fn rvm_guest_add_memory_region(
    rvm_dev: *mut c_void,
    guest_phys_addr: c_ulong,
    memory_size: c_ulong,
) -> c_int {
    let dev = RvmDev::from_raw(rvm_dev);
    retval(dev.guest_add_memory_region(guest_phys_addr as _, memory_size as _))
}

#[no_mangle]
unsafe extern "C" fn rvm_vcpu_create(rvm_dev: *mut c_void, entry: c_ulong) -> c_int {
    let dev = RvmDev::from_raw_mut(rvm_dev);
    retval(dev.vcpu_create(entry))
}

#[no_mangle]
unsafe extern "C" fn rvm_gpa_to_hpa(
    rvm_dev: *mut c_void,
    guest_phys_addr: c_ulong,
    alloc: bool,
) -> c_int {
    let dev = RvmDev::from_raw(rvm_dev);
    retval(dev.gpa_to_hpa(guest_phys_addr as _, alloc))
}

mod rvm_extern_fn {
    use crate::ffi::*;
    #[rvm::extern_fn(alloc_frame)]
    pub unsafe fn rvm_alloc_frame() -> Option<usize> {
        Some(__virt_to_phys(__get_free_pages(GFP_KERNEL, 0) as _))
    }

    #[rvm::extern_fn(dealloc_frame)]
    pub unsafe fn rvm_dealloc_frame(paddr: usize) {
        free_pages(__phys_to_virt(paddr) as _, 0)
    }

    #[rvm::extern_fn(phys_to_virt)]
    pub unsafe fn rvm_phys_to_virt(paddr: usize) -> usize {
        __phys_to_virt(paddr) as usize
    }

    #[cfg(target_arch = "x86_64")]
    #[rvm::extern_fn(x86_all_traps_handler_addr)]
    pub unsafe fn rvm_x86_all_traps_handler_addr() -> usize {
        0
    }
}
