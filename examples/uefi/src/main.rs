#![no_std]
#![no_main]
#![feature(asm)]
#![feature(abi_efiapi)]

extern crate alloc;
#[macro_use]
extern crate log;

use alloc::sync::Arc;
use rvm::*;
use uefi::prelude::*;
use uefi::table::boot::*;
use x86_64::{
    structures::paging::{PageTable, PageTableFlags as PTF},
    PhysAddr,
};

unsafe extern "C" fn hypercall() {
    for i in 0..100 {
        asm!(
            "vmcall",
            inout("ax") i => _,
            in("bx") 2,
            in("cx") 3,
            in("dx") 3,
            in("si") 3,
        );
    }
    asm!("mov qword ptr [$0xfff233], $2333");
}

fn setup() -> RvmResult<(Arc<Guest>, Vcpu)> {
    if !check_hypervisor_feature() {
        return Err(RvmError::NotSupported);
    }

    let entry = 0x2000;
    let gpm = DefaultGuestPhysMemorySet::new();
    let guest = Guest::new(gpm)?;
    let vcpu = Vcpu::new(entry as u64, guest.clone())?;

    let hpaddr0 = alloc_frame().unwrap();
    let hpaddr1 = alloc_frame().unwrap();
    let hpaddr2 = alloc_frame().unwrap();
    guest.add_memory_region(0, 0x1000, Some(hpaddr0))?;
    guest.add_memory_region(0x1000, 0x1000, Some(hpaddr1))?;
    guest.add_memory_region(0x2000, 0x1000, Some(hpaddr2))?;
    unsafe {
        core::ptr::copy(hypercall as usize as *const u8, hpaddr2 as *mut u8, 0x100);
    }

    // Delay mapping
    guest.add_memory_region(0x3000, 0x1000 * 10, None)?;

    // Set MMIO trap
    guest.set_trap(TrapKind::GuestTrapMem, 0xfff000, 0x1000, None, 0x2333)?;

    // Create guest page table
    let pt0 = unsafe { &mut *(hpaddr0 as *mut PageTable) };
    let pt1 = unsafe { &mut *(hpaddr1 as *mut PageTable) };
    pt0[0].set_addr(
        PhysAddr::new(0x1000),
        PTF::PRESENT | PTF::WRITABLE | PTF::USER_ACCESSIBLE,
    );
    pt1[0].set_addr(
        PhysAddr::new(0),
        PTF::PRESENT | PTF::WRITABLE | PTF::USER_ACCESSIBLE | PTF::HUGE_PAGE, // 1GB page
    );

    Ok((guest, vcpu))
}

fn run_hypervisor() -> RvmResult {
    let (_guest, mut vcpu) = setup()?;
    vcpu.write_state(&VcpuState {
        rax: 1,
        rbx: 2,
        rcx: 3,
        rdx: 4,
        rsp: 0x8000,
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
        rflags: 0,
    })?;

    let packet = vcpu.resume()?;
    let state = vcpu.read_state()?;
    info!("{:#x?}", packet);
    info!("{:#x?}", state);

    assert_eq!(packet.kind, RvmExitPacketKind::GuestMmio);
    assert_eq!(packet.key, 0x2333);
    assert_eq!(unsafe { packet.inner.mmio.addr }, 0xfff233);
    assert_eq!(unsafe { packet.inner.mmio.inst_len }, 0xc);
    assert_eq!(unsafe { packet.inner.mmio.default_operand_size }, 0x4);
    assert_eq!(
        unsafe { &packet.inner.mmio.inst_buf[0..12] },
        &[0x48, 0xc7, 0x4, 0x25, 0x33, 0xf2, 0xff, 0x0, 0x1d, 0x9, 0x0, 0x0]
    );
    assert_eq!(state.rflags, 0x44);
    info!("Run hypervisor successfully!");

    Ok(())
}

#[entry]
fn efi_main(_image: uefi::Handle, st: SystemTable<Boot>) -> Status {
    // Initialize utilities (logging, memory allocation...)
    uefi_services::init(&st).expect_success("failed to initialize utilities");
    // log::set_max_level(log::LevelFilter::Trace);
    info!("RVM example");

    setup_tss();
    run_hypervisor().unwrap();

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
    use x86_64::VirtAddr;

    let tss = Box::new(TaskStateSegment::new());
    let tss: &'static _ = Box::leak(tss);
    let (tss0, tss1) = match Descriptor::tss_segment(tss) {
        Descriptor::SystemSegment(tss0, tss1) => (tss0, tss1),
        _ => unreachable!(),
    };

    unsafe {
        // get current GDT
        let mut gdtp = core::mem::MaybeUninit::<DescriptorTablePointer>::uninit();
        asm!("sgdt [{}]", in(reg) gdtp.as_mut_ptr());
        let gdtp = gdtp.assume_init();
        let entry_count = (gdtp.limit + 1) as usize / size_of::<u64>();
        let old_gdt = core::slice::from_raw_parts(gdtp.base.as_ptr::<u64>(), entry_count);

        // allocate new GDT with 2 more entries
        let mut gdt = Vec::from(old_gdt);
        gdt.extend([tss0, tss1].iter());
        let gdt = Vec::leak(gdt);

        // load new GDT and TSS
        lgdt(&DescriptorTablePointer {
            limit: gdt.len() as u16 * 8 - 1,
            base: VirtAddr::new(gdt.as_ptr() as u64),
        });
        load_tss(SegmentSelector::new(
            entry_count as u16,
            PrivilegeLevel::Ring0,
        ));
    }
}

#[rvm::extern_fn(alloc_frame)]
fn alloc_frame() -> Option<usize> {
    let st = unsafe { &*uefi_services::system_table().as_ptr() };
    let paddr = st
        .boot_services()
        .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
        .expect_success("failed to allocate pages");
    trace!("alloc_frame: {:#x}", paddr);
    Some(paddr as usize)
}

#[rvm::extern_fn(dealloc_frame)]
fn dealloc_frame(paddr: usize) {
    let st = unsafe { &*uefi_services::system_table().as_ptr() };
    st.boot_services()
        .free_pages(paddr as u64, 1)
        .expect_success("failed to free pages");
    trace!("dealloc_frame: {:#x}", paddr);
}

/// Convert physical address to virtual address
#[rvm::extern_fn(phys_to_virt)]
fn phys_to_virt(paddr: usize) -> usize {
    paddr
}

/// Do not inject interrupts to guest
#[rvm::extern_fn(is_host_timer_interrupt)]
fn rvm_is_host_timer_interrupt(_vector: u8) -> bool {
    false
}

/// Do not inject interrupts to guest
#[rvm::extern_fn(is_host_serial_interrupt)]
fn rvm_is_host_serial_interrupt(_vector: u8) -> bool {
    false
}
