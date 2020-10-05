#![allow(dead_code)]
#![allow(non_camel_case_types)]

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

pub const GFP_KERNEL: c_uint = 0xCC0;

extern "C" {
    pub fn krealloc(p: *const c_void, new_size: c_size_t, flags: c_uint) -> *mut c_void;
    pub fn kfree(ptr: *const c_void);
    pub fn printk(fmt: *const c_char) -> c_int;
}
