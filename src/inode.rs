//! Implement INode for Rcore Virtual Machine

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc};
use core::any::Any;
use spin::RwLock;

use rcore_fs::vfs::*;

use super::arch::{self, Guest, Vcpu};
use super::packet::RvmExitPacket;
use crate::memory::copy_from_user;

const MAX_GUEST_NUM: usize = 64;
const MAX_VCPU_NUM: usize = 64;

const RVM_IO: u32 = 0xAE00;
const RVM_GUEST_CREATE: u32 = RVM_IO + 0x01;
const RVM_GUEST_ADD_MEMORY_REGION: u32 = RVM_IO + 0x02;
const RVM_GUEST_SET_TRAP: u32 = RVM_IO + 0x03;
const RVM_VCPU_CREATE: u32 = RVM_IO + 0x11;
const RVM_VCPU_RESUME: u32 = RVM_IO + 0x12;
const RVM_VCPU_WRITE_STATE: u32 = RVM_IO + 0x13;
const RVM_VCPU_READ_STATE: u32 = RVM_IO + 0x14;
const RVM_VCPU_INTERRUPT: u32 = RVM_IO + 0x15;

pub struct RvmINode {
    guests: RwLock<BTreeMap<usize, Arc<Box<Guest>>>>,
    vcpus: RwLock<BTreeMap<usize, Box<Vcpu>>>,
}

#[repr(C)]
#[derive(Debug)]
struct RvmVcpuCreateArgs {
    vmid: u16,
    entry: u64,
}

#[repr(C)]
#[derive(Debug)]
struct RvmGuestAddMemoryRegionArgs {
    vmid: u16,
    guest_start_paddr: u64,
    memory_size: u64,
}

#[repr(C)]
#[derive(Debug)]
struct RvmGuestSetTrapArgs {
    vmid: u16,
    kind: u32,
    addr: u64,
    size: u64,
    key: u64,
}

#[repr(C)]
#[derive(Debug)]
struct RvmVcpuResumeArgs {
    vcpu_id: u16,
    packet: RvmExitPacket,
}

#[repr(C)]
#[derive(Debug)]
pub struct RvmGuestState {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
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
}

#[repr(C)]
#[derive(Debug)]
struct RvmVcpuStateArgs {
    vcpu_id: u16,
    guest_state: RvmGuestState,
}

#[repr(C)]
#[derive(Debug)]
struct RvmVcpuInterruptArgs {
    vcpu_id: u16,
    vector: u32,
}

impl INode for RvmINode {
    fn read_at(&self, _offset: usize, _buf: &mut [u8]) -> Result<usize> {
        Err(FsError::NotSupported)
    }
    fn write_at(&self, _offset: usize, _buf: &[u8]) -> Result<usize> {
        Err(FsError::NotSupported)
    }
    fn poll(&self) -> Result<PollStatus> {
        Ok(PollStatus {
            read: false,
            write: false,
            error: false,
        })
    }
    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata {
            dev: 0,
            inode: 0,
            size: 0,
            blk_size: 0,
            blocks: 0,
            atime: Timespec { sec: 0, nsec: 0 },
            mtime: Timespec { sec: 0, nsec: 0 },
            ctime: Timespec { sec: 0, nsec: 0 },
            type_: FileType::CharDevice,
            mode: 0o660,
            nlinks: 1,
            uid: 0,
            gid: 0,
            rdev: make_rdev(10, 232), // misc major, kvm minor
        })
    }
    fn io_control(&self, cmd: u32, data: usize) -> Result<usize> {
        match cmd {
            RVM_GUEST_CREATE => {
                info!("[RVM] ioctl RVM_GUEST_CREATE");
                if arch::check_hypervisor_feature() {
                    let vmid = self.get_free_vmid();
                    if vmid >= MAX_GUEST_NUM {
                        warn!("[RVM] too many guests ({})", MAX_GUEST_NUM);
                        return Err(FsError::NoDeviceSpace);
                    }
                    let guest = Guest::new()?;
                    assert!(self.add_guest(guest) == vmid);
                    Ok(vmid)
                } else {
                    warn!("[RVM] no hardware support");
                    Err(FsError::NotSupported)
                }
            }
            RVM_GUEST_ADD_MEMORY_REGION => {
                let args = copy_from_user(data as *const RvmGuestAddMemoryRegionArgs)
                    .ok_or(FsError::InvalidParam)?;
                let vmid = args.vmid as usize;
                let guest_start_paddr = args.guest_start_paddr as usize;
                let memory_size = args.memory_size as usize;
                info!("[RVM] ioctl RVM_GUEST_ADD_MEMORY_REGION {:x?}", args);
                if let Some(guest) = self.guests.read().get(&vmid) {
                    guest.add_memory_region(guest_start_paddr, memory_size)
                } else {
                    Err(FsError::InvalidParam)
                }
            }
            RVM_GUEST_SET_TRAP => {
                let args = copy_from_user(data as *const RvmGuestSetTrapArgs)
                    .ok_or(FsError::InvalidParam)?;
                let vmid = args.vmid as usize;
                info!("[RVM] ioctl RVM_GUEST_SET_TRAP {:x?}", args);
                if let Some(guest) = self.guests.read().get(&vmid) {
                    use core::convert::TryInto;
                    guest.set_trap(
                        args.kind.try_into()?,
                        args.addr as usize,
                        args.size as usize,
                        args.key,
                    )?;
                    Ok(0)
                } else {
                    Err(FsError::InvalidParam)
                }
            }
            RVM_VCPU_CREATE => {
                let args = copy_from_user(data as *const RvmVcpuCreateArgs)
                    .ok_or(FsError::InvalidParam)?;
                let vmid = args.vmid as usize;
                info!("[RVM] ioctl RVM_VCPU_CREATE {:x?}", args);
                if let Some(guest) = self.guests.read().get(&vmid) {
                    let vpid = self.get_free_vpid();
                    if vpid >= MAX_VCPU_NUM {
                        warn!("[RVM] too many vcpus ({})", MAX_VCPU_NUM);
                        return Err(FsError::NoDeviceSpace);
                    }
                    let mut vcpu = Vcpu::new(vpid as u16, guest.clone())?;
                    vcpu.init(args.entry)?;
                    assert!(self.add_vcpu(vcpu) == vpid);
                    Ok(vpid)
                } else {
                    Err(FsError::InvalidParam)
                }
            }
            RVM_VCPU_RESUME => {
                let args = copy_from_user(data as *const RvmVcpuResumeArgs)
                    .ok_or(FsError::InvalidParam)?;
                let vpid = args.vcpu_id as usize;
                info!("[RVM] ioctl RVM_VCPU_RESUME {:#x}", vpid);
                if let Some(vcpu) = self.vcpus.write().get_mut(&vpid) {
                    // FIXME: implement copy to user
                    let mut args = unsafe { &mut *(data as *mut RvmVcpuResumeArgs) };
                    args.packet = vcpu.resume()?;
                    Ok(0)
                } else {
                    Err(FsError::InvalidParam)
                }
            }
            RVM_VCPU_WRITE_STATE => {
                let args =
                    copy_from_user(data as *const RvmVcpuStateArgs).ok_or(FsError::InvalidParam)?;
                let vpid = args.vcpu_id as usize;
                info!("[RVM] ioctl RVM_VCPU_WRITE_STATE {:#x} {:#x?}", vpid, args);
                if let Some(vcpu) = self.vcpus.write().get_mut(&vpid) {
                    vcpu.write_state(args.guest_state)?;
                    Ok(0)
                } else {
                    Err(FsError::InvalidParam)
                }
            }
            RVM_VCPU_READ_STATE => {
                let args =
                    copy_from_user(data as *const RvmVcpuStateArgs).ok_or(FsError::InvalidParam)?;
                let vpid = args.vcpu_id as usize;
                info!("[RVM] ioctl RVM_VCPU_READ_STATE {:#x}", vpid);
                if let Some(vcpu) = self.vcpus.write().get_mut(&vpid) {
                    // FIXME: implement copy to user
                    let mut args = unsafe { &mut *(data as *mut RvmVcpuStateArgs) };
                    args.guest_state = vcpu.read_state()?;
                    Ok(0)
                } else {
                    Err(FsError::InvalidParam)
                }
            }
            RVM_VCPU_INTERRUPT => {
                let args = copy_from_user(data as *const RvmVcpuInterruptArgs)
                    .ok_or(FsError::InvalidParam)?;
                let vpid = args.vcpu_id as usize;
                info!("[RVM] ioctl RVM_VCPU_INTERRUPT {:#x} {:#x?}", vpid, args);
                if let Some(vcpu) = self.vcpus.write().get_mut(&vpid) {
                    vcpu.virtual_interrupt(args.vector)?;
                    Ok(0)
                } else {
                    Err(FsError::InvalidParam)
                }
            }
            _ => {
                warn!("[RVM] invalid ioctl number {:#x}", cmd);
                Err(FsError::InvalidParam)
            }
        }
    }
    fn mmap(&self, area: MMapArea) -> Result<()> {
        info!("[RVM] mmap {:x?}", area);
        Err(FsError::NotSupported)
    }
    fn as_any_ref(&self) -> &dyn Any {
        self
    }
}

impl RvmINode {
    pub fn new() -> Self {
        Self {
            guests: RwLock::new(BTreeMap::new()),
            vcpus: RwLock::new(BTreeMap::new()),
        }
    }

    fn get_free_vmid(&self) -> usize {
        (1..).find(|i| !self.guests.read().contains_key(i)).unwrap()
    }

    fn add_guest(&self, guest: Box<Guest>) -> usize {
        let vmid = self.get_free_vmid();
        self.guests.write().insert(vmid, Arc::new(guest));
        vmid
    }

    fn get_free_vpid(&self) -> usize {
        (1..).find(|i| !self.vcpus.read().contains_key(i)).unwrap()
    }

    fn add_vcpu(&self, vcpu: Box<Vcpu>) -> usize {
        let vpid = self.get_free_vpid();
        self.vcpus.write().insert(vpid, vcpu);
        vpid
    }

    // TODO: remove guest & vcpu
}
