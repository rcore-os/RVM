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
mod dummy;
mod ffi;
mod interrupt;
mod memory;
mod packet;
mod trap_map;

#[cfg(target_arch = "x86_64")]
pub use arch::{check_hypervisor_feature, ArchRvmPageTable, Guest, GuestState, Vcpu};
pub use dummy::DefaultGuestPhysMemorySet;
pub use memory::*;
pub use rvm_macros::*;
pub use trap_map::TrapKind;

pub type RvmResult<T = ()> = Result<T, RvmError>;

#[derive(Debug)]
pub enum RvmError {
    Internal,
    NotSupported,
    NoMemory,
    InvalidParam,
    OutOfRange,
    BadState,
    NotFound,
}
