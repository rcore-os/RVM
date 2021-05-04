#![allow(dead_code)]
#![allow(non_camel_case_types)]

pub mod ctypes {
    pub type c_int = i32;
    pub type c_char = i8;
    pub type c_long = i64;
    pub type c_longlong = i64;
    pub type c_short = i16;
    pub type c_uchar = u8;
    pub type c_uint = u32;
    pub type c_ulong = u64;
    pub type c_ulonglong = u64;
    pub type c_ushort = u16;
    pub type c_schar = i8;
    pub type c_size_t = usize;
    pub type c_ssize_t = isize;
    pub type c_void = core::ffi::c_void;
}
use ctypes::*;

pub const PAGE_SIZE: usize = 0x1000;
pub const GFP_KERNEL: c_uint = 0xCC0;

pub const LOCAL_TIMER_VECTOR: u8 = 0xEC;

extern "C" {
    // symbols in kernel
    pub fn krealloc(p: *const c_void, new_size: c_size_t, flags: c_uint) -> *mut c_void;
    pub fn kfree(ptr: *const c_void);
    pub fn printk(fmt: *const c_char) -> c_int;
    pub fn __get_free_pages(gfp_mask: c_uint, order: c_uint) -> c_ulong;
    pub fn free_pages(addr: c_ulong, order: c_uint);

    // symbols in rvm_module.c for wrapping definitions
    pub fn __phys_to_virt(address: c_size_t) -> *mut c_void;
    pub fn __virt_to_phys(address: *mut c_void) -> c_size_t;
    pub fn __BUG();
}
