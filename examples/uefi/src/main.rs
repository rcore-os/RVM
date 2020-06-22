#![no_std]
#![no_main]
#![feature(abi_efiapi)]

extern crate alloc;
#[macro_use]
extern crate log;
extern crate rlibc;

use rvm::*;
use uefi::prelude::*;
use uefi::table::boot::*;

#[entry]
fn efi_main(image: uefi::Handle, st: SystemTable<Boot>) -> Status {
    // Initialize utilities (logging, memory allocation...)
    uefi_services::init(&st).expect_success("failed to initialize utilities");
    // log::set_max_level(log::LevelFilter::Trace);
    info!("RVM example");

    let guest = Guest::new().unwrap();
    let mut vcpu = Vcpu::new(0, guest.clone()).unwrap();

    vcpu.write_state(&vcpu::GuestState {
        xcr0: 0,
        cr2: 0,
        rax: 1,
        rbx: 2,
        rcx: 3,
        rdx: 4,
        rbp: 5,
        rsi: 6,
        rdi: 7,
        r8: 8,
        r9: 9,
        r10: 10,
        r11: 11,
        r12: 12,
        r13: 13,
        r14: 14,
        r15: 15,
    })
    .unwrap();

    vcpu.resume();

    info!("{:#x?}", vcpu.read_state().unwrap());

    panic!();
}

#[no_mangle]
extern "C" fn alloc_frame() -> usize {
    let st = unsafe { &*uefi_services::system_table().as_ptr() };
    let paddr = st
        .boot_services()
        .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
        .expect_success("failed to allocate pages");
    trace!("alloc_frame: {:#x}", paddr);
    paddr as usize
}

#[no_mangle]
extern "C" fn dealloc_frame(paddr: usize) {
    let st = unsafe { &*uefi_services::system_table().as_ptr() };
    st.boot_services()
        .free_pages(paddr as u64, 1)
        .expect_success("failed to free pages");
    trace!("dealloc_frame: {:#x}", paddr);
}

/// Convert physical address to virtual address
#[no_mangle]
extern "C" fn phys_to_virt(paddr: usize) -> usize {
    paddr
}
