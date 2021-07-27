# RVM -- Rcore Virtual Machine

[![CI](https://github.com/rcore-os/RVM/workflows/CI/badge.svg?branch=master)](https://github.com/rcore-os/RVM/actions)

An experimental hypervisor library written in Rust to build both type-1 and type-2 hypervisors.

Supported architecture: x86_64 (Intel VMX).

## rustc info
- current rustc -- rustc 1.56.0-nightly (08095fc1f 2021-07-26)
- current rust-toolchain -- nightly
 

## Basic usage

See the [UEFI example](examples/uefi/src/main.rs) for more details.

```rust
use rvm::*;

const ENTRY: u64 = 0x2000;

fn run_hypervisor() -> RvmResult {
    // create a guest physical memory set.
    let gpm = DefaultGuestPhysMemorySet::new();

    // create a guest.
    let guest = Guest::new(gpm)?;

    // create a vcpu.
    let mut vcpu = Vcpu::new(ENTRY, guest.clone())?;

    // map the guest physical memory region [0, 0x8000) to the host phyical
    // memory region [0xC0000, 0xC8000).
    let host_paddr = 0xC0000;
    guest.add_memory_region(0, 0x8000, Some(0xC0000))?;

    // I/O instructions with port 0x233-0x234 can cause VM exit and `vcpu.resume()`
    // to return.
    guest.set_trap(TrapKind::GuestTrapIo, 0x233, 2, None, 0xdeadbeef)?;

    // The bootstrap processor is in IA-32e mode and enabled paging, you need to
    // setup guest page table.
    setup_guest_page_table(host_paddr);

    // run the VCPU and block, until the specified traps occurs.
    let packet = vcpu.resume()?;

    // get the VCPU state.
    let state = vcpu.read_state()?;

    Ok(())
}
```

## More examples

RVM is used as the hypervisor module of the following OSes:

* [rCore](https://github.com/rcore-os/rCore)
* [zCore](https://github.com/rcore-os/zCore)

It can also run in linux as a kernel module and replace the [KVM](https://www.linux-kvm.org/page/Main_Page) hypervisor to support simple guest OSes such as [uCore](https://github.com/chyyuu/os_kernel_lab/tree/master). See the [ko example](examples/ko) and [rcore-vmm](https://github.com/rcore-os/rcore-vmm) for more details.

## Documents

* [in Chinese](https://github.com/rcore-os/RVM/wiki)
