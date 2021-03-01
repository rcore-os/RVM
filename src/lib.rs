//! Rcore Virtual Machine

#![no_std]
#![feature(asm)]
#![feature(llvm_asm)]
#![feature(global_asm)]
#![feature(untagged_unions)]
#![allow(clippy::upper_case_acronyms)]
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
pub use arch::{check_hypervisor_feature, ArchRvmPageTable, Guest, Vcpu};
pub use dummy::{DefaultGuestPhysMemorySet, GuestMemoryAttr};
pub use memory::*;
pub use packet::*;
pub use rvm_macros::*;
pub use trap_map::{RvmPort, TrapKind};

pub type RvmResult<T = ()> = Result<T, RvmError>;

#[derive(Debug, PartialEq)]
pub enum RvmError {
    Internal,
    NotSupported,
    NoMemory,
    InvalidParam,
    OutOfRange,
    BadState,
    NotFound,
}

use numeric_enum_macro::numeric_enum;

numeric_enum! {
    #[repr(u32)]
    #[derive(Debug)]
    pub enum VcpuReadWriteKind {
        VcpuState = 0,
        VcpuIo = 1,
    }
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Default)]
pub struct VcpuState {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    // Contains only the user-controllable lower 32-bits.
    pub rflags: u64,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Default)]
pub struct VcpuState {
    pub x: [u64; 31],
    pub sp: u64,
    pub cpsr: u64,
    pub _padding1: [u8; 4],
}

#[repr(C)]
#[derive(Debug)]
pub struct VcpuIo {
    pub access_size: u8,
    pub _padding1: [u8; 3],
    pub data: [u8; 4],
}
