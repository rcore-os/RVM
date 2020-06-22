#![no_std]
#![no_main]
#![feature(abi_efiapi)]

extern crate alloc;
#[macro_use]
extern crate log;
extern crate rlibc;

use uefi::prelude::*;

#[entry]
fn efi_main(image: uefi::Handle, st: SystemTable<Boot>) -> Status {
    // Initialize utilities (logging, memory allocation...)
    uefi_services::init(&st).expect_success("failed to initialize utilities");

    info!("RVM example");
    panic!();
}
