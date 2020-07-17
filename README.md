# RVM -- Rcore Virtual Machine

[![CI](https://github.com/rcore-os/RVM/workflows/CI/badge.svg?branch=master)](https://github.com/rcore-os/RVM/actions)

A small hypervisor for [zCore OS](https://github.com/rcore-os/zCore) or bare-metal.

Supported architecture: x86_64 (Intel VMX).

## Basic usage

See the [UEFI example](examples/uefi/src/main.rs)for more detail.

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

    // run the VCPU and block, until the specified traps occurs.
    let packet = vcpu.resume()?;

    // get the VCPU state.
    let state = vcpu.read_state()?;

    Ok(())
}
```
