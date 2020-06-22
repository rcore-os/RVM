//! Rcore Virtual Machine

#![no_std]
#![feature(asm)]
#![feature(linkage)]
#![feature(naked_functions)]
#![feature(untagged_unions)]

#[macro_use]
extern crate alloc;
#[macro_use]
extern crate log;

#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/mod.rs"]
mod arch;
mod interrupt;
mod memory;
mod packet;
mod trap_map;

pub use arch::Guest;
pub use arch::Vcpu;

pub type RvmResult<T = ()> = Result<T, RvmError>;

#[derive(Debug)]
pub enum RvmError {
    NotSupported,
    NoDeviceSpace,
    InvalidParam,
    DeviceError,
}
