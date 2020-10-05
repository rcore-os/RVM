use alloc::boxed::Box;

use crate::ffi::c_void;

#[repr(C)]
#[derive(Debug)]
struct RvmDev {
    guest_num: usize,
    vcpu_num: usize,
}

impl RvmDev {
    fn new() -> Self {
        info!("NEW");
        Self {
            guest_num: 0,
            vcpu_num: 0,
        }
    }
}

impl Drop for RvmDev {
    fn drop(&mut self) {
        info!("DROP");
    }
}

#[no_mangle]
extern "C" fn new_rvm_dev() -> *mut c_void {
    Box::into_raw(Box::new(RvmDev::new())) as *mut c_void
}

#[no_mangle]
extern "C" fn free_rvm_dev(rvm_dev: *mut c_void) {
    unsafe { drop(Box::from_raw(rvm_dev as *mut RvmDev)) };
}

#[no_mangle]
extern "C" fn hello() {
    println!("HELLO print");
    info!("HELLO INFO");
    warn!("HELLO WARN");
    error!("HELLO ERROR");
    debug!("HELLO debug");
    trace!("HELLO trace");
}
