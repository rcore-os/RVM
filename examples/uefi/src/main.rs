#![no_std]
#![no_main]
#![feature(asm)]
#![feature(vec_leak)]
#![feature(abi_efiapi)]
#![feature(llvm_asm)]

extern crate alloc;
#[macro_use]
extern crate log;
extern crate rlibc;

use rvm::*;
use uefi::prelude::*;
use uefi::table::boot::*;

pub unsafe extern "C" fn hypercall() {
    for i in 0.. {
        llvm_asm!(
            "vmcall"
            :
            : "{ax}"(i),
              "{bx}"(2),
              "{cx}"(3),
              "{dx}"(3),
              "{si}"(3)
            :
            : "volatile");
    }
}

#[entry]
fn efi_main(image: uefi::Handle, st: SystemTable<Boot>) -> Status {
    // Initialize utilities (logging, memory allocation...)
    uefi_services::init(&st).expect_success("failed to initialize utilities");
    // log::set_max_level(log::LevelFilter::Trace);
    info!("RVM example");

    setup_tss();
    let entry = 0x1000;
    let guest = Guest::new().unwrap();
    let mut vcpu = Vcpu::new(1, entry as u64, guest.clone()).unwrap();

    for i in 0..0x10 {
        let guest_paddr = i * 0x1000;
        let host_paddr = alloc_frame();
        if guest_paddr == entry {
            unsafe {
                core::ptr::copy(
                    hypercall as usize as *const u8,
                    host_paddr as *mut u8,
                    0x100,
                );
            }
        }
        guest.add_memory_region(guest_paddr, host_paddr, 0x1000);
    }

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

/// Extend GDT and setup TSS.
fn setup_tss() {
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use core::mem::size_of;
    use x86_64::instructions::tables::{lgdt, load_tss};
    use x86_64::structures::gdt::{Descriptor, SegmentSelector};
    use x86_64::structures::tss::TaskStateSegment;
    use x86_64::structures::DescriptorTablePointer;
    use x86_64::PrivilegeLevel;

    let tss = Box::new(TaskStateSegment::new());
    let tss: &'static _ = Box::leak(tss);
    let (tss0, tss1) = match Descriptor::tss_segment(tss) {
        Descriptor::SystemSegment(tss0, tss1) => (tss0, tss1),
        _ => unreachable!(),
    };

    unsafe {
        // get current GDT
        let mut gdtp = DescriptorTablePointer { limit: 0, base: 0 };
        asm!("sgdt [{}]", in(reg) &mut gdtp);
        let entry_count = (gdtp.limit + 1) as usize / size_of::<u64>();
        let old_gdt = core::slice::from_raw_parts(gdtp.base as *const u64, entry_count);

        // allocate new GDT with 2 more entries
        let mut gdt = Vec::from(old_gdt);
        gdt.extend([tss0, tss1].iter());
        let gdt = Vec::leak(gdt);

        // load new GDT and TSS
        lgdt(&DescriptorTablePointer {
            limit: gdt.len() as u16 * 8 - 1,
            base: gdt.as_ptr() as _,
        });
        load_tss(SegmentSelector::new(
            entry_count as u16,
            PrivilegeLevel::Ring0,
        ));
    }
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
