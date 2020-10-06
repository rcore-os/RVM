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

const MAX_GUEST_NUM: usize = 32;
const MAX_VCPU_NUM: usize = 32;

#[repr(C)]
#[derive(Debug)]
struct RvmDev {
    guests: Vec<Arc<Guest>>,
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
            guests: Vec::new(),
            vcpus: Vec::new(),
        }
    }

    fn guest_create(&mut self) -> KernelResult {
        let vmid = self.guests.len() + 1;
        if vmid > MAX_GUEST_NUM {
            warn!("[RVM] too many guests (maximum is {})", MAX_GUEST_NUM);
            return Err(KernelError::ENOMEM);
        }
        let gpm = DefaultGuestPhysMemorySet::new();
        let guest = Guest::new(gpm)?;
        self.guests.push(guest);
        Ok(vmid)
    }

    fn vcpu_create(&mut self, vmid: usize, entry: u64) -> KernelResult {
        if vmid == 0 || vmid > self.guests.len() {
            warn!("[RVM] invalid vmid {}", vmid);
            return Err(KernelError::EINVAL);
        }
        let vcpu_id = self.vcpus.len() + 1;
        if vcpu_id > MAX_VCPU_NUM {
            warn!("[RVM] too many vcpus (maximum is {})", MAX_VCPU_NUM);
            return Err(KernelError::ENOMEM);
        }
        let guest = self.guests[vmid - 1].clone();
        let vcpu = Mutex::new(Vcpu::new(entry, guest)?);
        self.vcpus.push(vcpu);
        Ok(vcpu_id)
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
unsafe extern "C" fn rvm_vcpu_create(
    rvm_dev: *mut c_void,
    vmid: c_ushort,
    entry: c_ulong,
) -> c_int {
    let dev = RvmDev::from_raw_mut(rvm_dev);
    retval(dev.vcpu_create(vmid as _, entry))
}

mod rvm_extern_fn {
    use crate::ffi::*;
    #[rvm::extern_fn(alloc_frame)]
    unsafe fn rvm_alloc_frame() -> Option<usize> {
        Some(__virt_to_phys(krealloc(
            core::ptr::null(),
            PAGE_SIZE,
            GFP_KERNEL,
        )))
    }

    #[rvm::extern_fn(dealloc_frame)]
    unsafe fn rvm_dealloc_frame(paddr: usize) {
        kfree(__phys_to_virt(paddr))
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
