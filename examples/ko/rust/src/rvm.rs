use alloc::{boxed::Box, sync::Arc, vec::Vec};
use spin::Mutex;

use rvm::{DefaultGuestPhysMemorySet, Guest, RvmError, Vcpu};

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
unsafe extern "C" fn rvm_vcpu_create(rvm_dev: *mut c_void, entry: c_ulong) -> c_int {
    let dev = RvmDev::from_raw_mut(rvm_dev);
    retval(dev.vcpu_create(entry))
}

mod rvm_extern_fn {
    use crate::ffi::*;
    #[rvm::extern_fn(alloc_frame)]
    unsafe fn rvm_alloc_frame() -> Option<usize> {
        Some(__virt_to_phys(__get_free_pages(GFP_KERNEL, 0) as _))
    }

    #[rvm::extern_fn(dealloc_frame)]
    unsafe fn rvm_dealloc_frame(paddr: usize) {
        free_pages(__phys_to_virt(paddr) as _, 0)
    }

    #[rvm::extern_fn(phys_to_virt)]
    unsafe fn rvm_phys_to_virt(paddr: usize) -> usize {
        __phys_to_virt(paddr) as usize
    }

    #[cfg(target_arch = "x86_64")]
    #[rvm::extern_fn(x86_all_traps_handler_addr)]
    unsafe fn rvm_x86_all_traps_handler_addr() -> usize {
        0
    }
}
