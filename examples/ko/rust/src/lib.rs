#![no_std]
#![feature(alloc_error_handler)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate alloc;

pub mod ffi;
#[macro_use]
pub mod logging;
pub mod rvm;

use core::alloc::{GlobalAlloc, Layout};
use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    error!("{}", info);
    loop {}
}

struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ffi::krealloc(core::ptr::null(), layout.size(), ffi::GFP_KERNEL) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        ffi::kfree(ptr as *const core::ffi::c_void);
    }
}

#[alloc_error_handler]
fn oom(_layout: Layout) -> ! {
    panic!("Out of memory!");
}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;
