//! Rcore Virtual Machine

#![no_std]
#![feature(asm)]
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
mod packet;
mod trap_map;

pub use arch::Guest;
pub use arch::Vcpu;

pub type RvmResult<T = ()> = Result<T, RvmError>;

pub enum RvmError {
    NotSupported,
    NoDeviceSpace,
    InvalidParam,
}
