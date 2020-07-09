//! Rcore Virtual Machine

#![no_std]
#![feature(llvm_asm)]
#![feature(naked_functions)]
#![feature(untagged_unions)]
#![deny(warnings)]

#[macro_use]
extern crate alloc;
#[macro_use]
extern crate log;

#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/mod.rs"]
mod arch;
mod ffi;
mod interrupt;
mod memory;
mod packet;
mod trap_map;

pub use arch::*;
pub use memory::*;
pub use rvm_macros::*;

pub type RvmResult<T = ()> = Result<T, RvmError>;

#[derive(Debug)]
pub enum RvmError {
    Internal,
    NotSupported,
    NoMemory,
    InvalidParam,
    OutOfRange,
    NotFound,

    // Deprecated
    NoDeviceSpace,
    DeviceError,
}
