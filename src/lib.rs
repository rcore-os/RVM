//! Rcore Virtual Machine

#![no_std]
#![feature(naked_functions)]

extern crate alloc;

#[cfg(target_arch = "x86_64")]
#[path = "arch/x86_64/mod.rs"]
mod arch;
mod inode;
mod interrupt;
mod packet;
mod trap_map;

type RvmError = rcore_fs::vfs::FsError;
type RvmResult<T> = rcore_fs::vfs::Result<T>;

pub use inode::RvmINode;
