use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::error::{retval, KernelError, KernelResult};
use crate::ffi::ctypes::*;

const MAX_GUEST_NUM: usize = 32;
const MAX_VCPU_NUM: usize = 32;

#[repr(C)]
#[derive(Debug)]
struct RvmDev {
    guests: Vec<usize>,
    vcpus: Vec<usize>,
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
        let guest = vmid;
        self.guests.push(guest);
        Ok(vmid)
    }

    fn vcpu_create(&mut self, vmid: usize, _entry: u64) -> KernelResult {
        if vmid == 0 || vmid > self.guests.len() {
            warn!("[RVM] invalid vmid {}", vmid);
            return Err(KernelError::EINVAL);
        }
        let vcpu_id = self.vcpus.len() + 1;
        if vcpu_id > MAX_VCPU_NUM {
            warn!("[RVM] too many vcpus (maximum is {})", MAX_VCPU_NUM);
            return Err(KernelError::ENOMEM);
        }
        let vcpu = vcpu_id;
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
