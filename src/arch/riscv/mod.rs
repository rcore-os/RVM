mod ptx4;
pub type ArchRvmPageTable = ptx4::PageTableSv48X4;
use crate::memory::{GuestPhysAddr, GuestPhysMemorySetTrait, HostPhysAddr};
use crate::trap_map::{RvmPort, TrapKind, TrapMap};
use crate::PAGE_SIZE;
use crate::{RvmError, RvmResult};
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;
use spin::RwLock;
pub fn check_hypervisor_feature() -> bool {
    // RISC-V does now allow checking hypervisor feature directly.
    // Instead, throw back the task to OS.
    crate::ffi::riscv_check_hypervisor_extension()
}
use core::sync::atomic::*;
static VMID_ALLOCATOR: AtomicUsize = AtomicUsize::new(1);
static INITIALIZED: AtomicUsize = AtomicUsize::new(0);
pub struct Guest {
    vmid: usize,
    gpm: Arc<dyn GuestPhysMemorySetTrait>,
    traps: Mutex<TrapMap>,
    interrupt_handlers: RwLock<Vec<Arc<InterruptState>>>,
}
impl Guest {
    pub fn get_irq_by_id(&self, cpuid: usize) -> Arc<InterruptState> {
        Arc::clone(self.interrupt_handlers.read().get(cpuid).unwrap())
    }
    fn alloc_cpuid(&self) -> usize {
        let mut irh = self.interrupt_handlers.write();
        let new_id = irh.len();
        irh.push(Arc::new(InterruptState::new()));
        new_id
    }
    pub fn use_pt(&self) {
        let mut val = hgatp::Hgatp::from_bits(0);
        val.set_vmid(self.vmid);
        val.set_ppn(self.rvm_page_table_phys() >> 12);
        val.set_mode(hgatp::HgatpValues::Sv48x4);
        unsafe {
            val.write();
        }
    }
    /// Create a new Guest.
    pub fn new(gpm: Arc<dyn GuestPhysMemorySetTrait>) -> RvmResult<Arc<Self>> {
        if INITIALIZED.swap(1, Ordering::Relaxed) == 0 {
            init_traps();
        }
        Ok(Arc::new(Self {
            vmid: VMID_ALLOCATOR.fetch_add(1, Ordering::Relaxed),
            gpm,
            traps: Mutex::new(TrapMap::default()),
            interrupt_handlers: RwLock::default(),
        }))
    }

    /// Get the page table base address.
    pub(crate) fn rvm_page_table_phys(&self) -> usize {
        self.gpm.table_phys()
    }

    pub fn add_memory_region(
        &self,
        gpaddr: GuestPhysAddr,
        size: usize,
        hpaddr: Option<HostPhysAddr>,
    ) -> RvmResult {
        if gpaddr & (PAGE_SIZE - 1) != 0 || size & (PAGE_SIZE - 1) != 0 {
            return Err(RvmError::InvalidParam);
        }
        if let Some(hpaddr) = hpaddr {
            if hpaddr & (PAGE_SIZE - 1) != 0 {
                return Err(RvmError::InvalidParam);
            }
        }
        self.gpm.map(gpaddr, size, hpaddr)
    }

    pub fn set_trap(
        &self,
        kind: TrapKind,
        addr: usize,
        size: usize,
        port: Option<Arc<dyn RvmPort>>,
        key: u64,
    ) -> RvmResult {
        if size == 0 {
            return Err(RvmError::InvalidParam);
        }
        if addr > usize::MAX - size {
            return Err(RvmError::OutOfRange);
        }
        match kind {
            TrapKind::GuestTrapIo => {
                return Err(RvmError::NotSupported);
            }
            TrapKind::GuestTrapBell => {
                return Err(RvmError::NotSupported);
            }
            TrapKind::GuestTrapMem => {
                if kind == TrapKind::GuestTrapBell && port.is_none() {
                    return Err(RvmError::InvalidParam);
                }
                if kind == TrapKind::GuestTrapMem && port.is_some() {
                    return Err(RvmError::InvalidParam);
                }
                if addr & (PAGE_SIZE - 1) != 0 || size & (PAGE_SIZE - 1) != 0 {
                    Err(RvmError::InvalidParam)
                } else {
                    self.gpm.unmap(addr, size)?;
                    self.traps.lock().push(kind, addr, size, port, key)
                }
            }
            _ => Err(RvmError::InvalidParam),
        }
    }
}

pub struct Vcpu {
    id: usize,
    state: VcpuState,
    running: core::sync::atomic::AtomicBool,
    guest: Arc<Guest>,
    interrupts: Arc<InterruptState>,
}
use crate::*;
use riscv::register::*;
use traps::*;
impl Vcpu {
    pub fn get_id(&self) -> usize {
        self.id
    }
    pub fn read_state(&self) -> RvmResult<VcpuState> {
        Ok(self.state)
    }

    pub fn write_state(&mut self, state: &VcpuState) -> RvmResult {
        self.state = *state;
        Ok(())
    }
    pub fn resume(&mut self) -> RvmResult<super::RvmExitPacket> {
        // init traps.
        init_traps();
        let mut yield_counter = 0;
        // load vm.
        self.state.privctx.restore();
        self.guest.use_pt();
        //let _vmctx = self.state.privctx.load(); // guard.
        loop {
            self.running
                .store(true, core::sync::atomic::Ordering::SeqCst);
            self.interrupts.apply();
            unsafe {
                runvm::resume_vm(&mut self.state.ctx);
            }
            self.running
                .store(false, core::sync::atomic::Ordering::SeqCst);
            // dispatch trap packets.
            match self.handle_trap_from_rvm()? {
                None => {
                    yield_counter += 1;
                    if yield_counter == 100 {
                        self.state.privctx = VMMContextPriv::dump();
                        return Ok(RvmExitPacket::new_yield_packet(
                            0,
                            YieldPacket { magic: 100 },
                        ));
                    }
                    continue;
                }
                Some(x) => {
                    self.state.privctx = VMMContextPriv::dump();
                    return Ok(x);
                }
            }
        }
    }

    fn handle_sbi_call(&mut self) -> Result<Option<RvmExitPacket>, RvmError> {
        use sbi::*;
        use SBICall::*;
        match try_handle_sbi_call(&mut self.state.ctx) {
            SetTimer { time_value } => {
                self.interrupts.set_timer(time_value);
                Ok(None)
            }
            GetSpecVersion(SBIRet { error, value }) => {
                *error = 0;
                *value = 0b0_0000011_00000000_00000000_00000000;
                Ok(None)
            }
            GetSBIImplID(SBIRet { error, value }) => {
                *error = 0;
                *value = 0x31764942534d5652; /* "RVMSBIv1" */
                Ok(None)
            }
            GetImplVersion(SBIRet { error, value }) => {
                *error = 0;
                *value = 0x1; /* 1 */
                Ok(None)
            }
            GetVendorID(SBIRet { error, value }) => {
                *error = 0;
                *value = 0x0;
                Ok(None)
            }
            GetArchID(SBIRet { error, value }) => {
                *error = 0;
                *value = 0x0;
                Ok(None)
            }
            GetMachineImplID(SBIRet { error, value }) => {
                *error = 0;
                *value = 0x0;
                Ok(None)
            }
            ProbeExtension(probe_eid, SBIRet { error, value }) => {
                *error = 0;
                if probe_eid == 0x10 || probe_eid == 0x00 || probe_eid == 0x54494D45 {
                    *value = 1;
                } else {
                    *value = 0;
                }
                Ok(None)
            }
            Unknown {
                eid,
                fid,
                arg0,
                arg1,
                arg2,
                arg3,
            } => Ok(Some(RvmExitPacket::new_ecall_packet(
                0,
                EcallPacket {
                    eid,
                    fid,
                    arg0,
                    arg1,
                    arg2,
                    arg3,
                },
            ))),
            //_ => Ok(None),
        }
    }

    fn handle_memory_fault(
        &mut self,
        read: bool,
        exec: bool,
    ) -> Result<Option<RvmExitPacket>, RvmError> {
        let v = htinst::read();
        if v == 0 {
            self.handle_memory_fault_by_decoding(read, exec)
        } else {
            self.handle_memory_fault_using_htinst(read, exec)
        }
    }
    fn handle_memory_fault_by_decoding(
        &mut self,
        read: bool,
        exec: bool,
    ) -> Result<Option<RvmExitPacket>, RvmError> {
        let guest_paddr = self.get_gpa();
        if let Ok(()) = self.guest.gpm.handle_page_fault(guest_paddr) {
            return Ok(None);
        }
        info!("guest_paddr: {}", guest_paddr);
        let sepc = self.state.ctx.sepc;
        if sepc % 2 != 0 {
            error!("sepc unaligned.");
            // RVC are not virtual instructions.
            return Err(RvmError::BadState);
        }
        let next_insn = decode::read_instruction(sepc).ok_or_else(|| {
            error!("bad instruction");
            RvmError::BadState
        })?;
        let (inst_len, insn, access) = match next_insn {
            decode::I(trapped_insn_32) => {
                if let Some(x) = decode::decode_memory_ops_rvi(trapped_insn_32) {
                    info!("insn32 ({:x}): {:?}", trapped_insn_32, x);
                    Some((4, trapped_insn_32 as usize, x))
                } else {
                    None
                }
            }
            decode::C(trapped_insn_16) => {
                if let Some(Some(x)) = decode::decode_memory_ops_rvc(trapped_insn_16) {
                    info!("insn16 ({:x}): {:?}", trapped_insn_16, x);
                    Some((2, trapped_insn_16 as usize, x))
                } else {
                    None
                }
            }
        }
        .ok_or(RvmError::BadState)?;
        Ok(Some(RvmExitPacket::new_mmio_packet(
            0,
            MmioPacket {
                access_size: access.access_size,
                extension: access.sign_extension,
                dstreg: access.dst,
                addr: guest_paddr as u64,
                execute: exec,
                read,
                insn: insn as u32,
                data: self.state.ctx.get(access.src) as u64,
                inst_len,
            },
        )))
    }
    fn get_gpa(&self) -> usize {
        (htval::read() << 2) | (stval::read() & 3)
    }
    fn handle_memory_fault_using_htinst(
        &mut self,
        read: bool,
        exec: bool,
    ) -> Result<Option<RvmExitPacket>, RvmError> {
        // at the very first, we check if there is delayed mapping.
        let guest_paddr = self.get_gpa();
        if let Ok(()) = self.guest.gpm.handle_page_fault(guest_paddr) {
            return Ok(None);
        }
        // first, walking onto MMIO in PT translation is BANNED.
        let v = htinst::read();
        if v == 0
            || v == 0x00002000
            || v == 0x00002020
            || v == 0x00003000
            || v == 0x00003020
            || ((v >> 32) != 0)
        {
            error!("Walking onto MMIO in PT");
            return Err(RvmError::BadState);
        }
        // then, running onto MMIO region is also BANNED.
        if exec {
            error!("Running onto MMIO");
            return Err(RvmError::BadState);
        }

        // third, unaligned accesses outta here.
        let alignment = pseudoinsn::get_addr_offset(v);
        if alignment != 0 {
            error!("unaligned access {}", alignment);
            return Err(RvmError::BadState);
        }
        // and now we can give out the result.

        let _trap = self
            .guest
            .traps
            .lock()
            .find(TrapKind::GuestTrapMem, guest_paddr)
            .ok_or(RvmError::NotFound);

        let (size, extension) = pseudoinsn::get_op_size_and_extension(v);
        let dst = pseudoinsn::get_dst_register(v);
        Ok(Some(RvmExitPacket::new_mmio_packet(
            0,
            //trap.key,
            MmioPacket {
                access_size: size as u8,
                extension,
                dstreg: dst as u8,
                addr: guest_paddr as u64,
                execute: exec,
                read,
                insn: v as u32,
                data: self.state.ctx.get(pseudoinsn::get_src_register(v) as u8) as u64,
                inst_len: match v & 0b10 {
                    0b10 => 4,
                    0b00 => 2,
                    _ => unreachable!(),
                },
            },
        )))
    }
    fn handle_virtual_instruction(&mut self) -> bool {
        let sepc = self.state.ctx.sepc;
        if sepc % 2 != 0 {
            // RVC are not virtual instructions.
            return false;
        }
        //info!("epc = {}", self.state.ctx.sepc);
        let trapped_insn = decode::read_instruction(sepc);
        let trapped_insn_u32: u32 = if let Some(decode::I(insn)) = trapped_insn {
            insn
        } else {
            return false;
        };
        let trapped_insn = trapped_insn_u32;
        //info!("trapped_insn = {}", trapped_insn);
        if trapped_insn == 0x10500073 {
            info!("[rvm] wfi.");
            self.state.ctx.sepc += 4;
            return true;
        }
        if (trapped_insn & 0b000000000000_00000_111_00000_1111111)
            == 0b000000000000_00000_010_00000_1110011
        {
            // csrrs
            let csr_id = trapped_insn >> 20;
            let rs = (trapped_insn >> 15) & 0b11111;
            let rd = (trapped_insn >> 7) & 0b11111;
            if rs == 0 {
                if csr_id == 0xc01 {
                    info!("[rvm] rdtime.");
                    let val = time::read();
                    self.state.ctx.set(rd as u8, val);
                    self.state.ctx.sepc += 4;
                    return true;
                }
            }
        }
        false
    }
    fn handle_trap_from_rvm(&mut self) -> Result<Option<RvmExitPacket>, RvmError> {
        use scause as S;
        use S::Exception as E;
        //use S::Interrupt as I;
        use S::Trap::*;
        let cause = scause::read().cause();
        info!("{:?}", cause);
        match cause {
            // the 5 exceptions.
            Exception(E::InstructionGuestPageFault) => {
                if let Ok(x) = self.handle_memory_fault(false, true) {
                    return Ok(x);
                } else {
                    error!(
                        "Guest trying to execute invalid GPA addr: 0x{:x} (epc=0x{:x}).",
                        self.get_gpa(),
                        sepc::read()
                    );
                    return Err(RvmError::BadState);
                }
            }
            Exception(E::LoadGuestPageFault) => {
                if let Ok(x) = self.handle_memory_fault(true, false) {
                    return Ok(x);
                } else {
                    error!(
                        "Guest trying to load invalid GPA addr: 0x{:x} (epc=0x{:x}).",
                        self.get_gpa(),
                        sepc::read()
                    );
                    return Err(RvmError::BadState);
                }
            }
            Exception(E::StoreGuestPageFault) => {
                if let Ok(x) = self.handle_memory_fault(false, false) {
                    return Ok(x);
                } else {
                    error!(
                        "Guest trying to store invalid GPA addr: 0x{:x} (epc=0x{:x}).",
                        self.get_gpa(),
                        sepc::read()
                    );
                    return Err(RvmError::BadState);
                }
            }
            Exception(E::VirtualInstruction) => {
                //info!("Virtual instruction found.");
                if sstatus::read().spp() == sstatus::SPP::Supervisor {
                    if self.handle_virtual_instruction() {
                        return Ok(None);
                    }
                }
                info!("Nope. Downgrade to bad instruction.");
                pass_down_exception(&mut self.state.ctx, 2, stval::read());
                return Ok(None);
            }
            Exception(E::VirtualSupervisorEnvCall) => {
                info!("Virtual machine SBI call. Automatically increasing epc with 4.");
                let sbi_ret = self.handle_sbi_call()?;
                self.state.ctx.sepc += 4;
                return Ok(sbi_ret);
            }
            // interrupts.
            Interrupt(interrupt) => {
                info!("Interrupt {:?}", interrupt);
                crate::ffi::riscv_trap_handler_no_frame(self.state.ctx.sepc);
                return Ok(None);
            }
            _ => panic!("Impossible arm {:?}.", cause),
        }
        //Err(RvmError::Internal)
    }

    pub fn write_io_state(&mut self, _state: &VcpuIo) -> RvmResult {
        Err(RvmError::NotSupported)
    }

    /*
    /// Inject a virtual interrupt.
    pub fn virtual_interrupt(&mut self, _vector: u32) -> RvmResult {
        self.state.interrupts.has_external_interrupt = true;
        Ok(())
    }
    */
    pub fn new(entry: u64, guest: Arc<Guest>) -> RvmResult<Self> {
        let cpuid = guest.alloc_cpuid();
        let irq = guest.get_irq_by_id(cpuid);
        Ok(Self {
            state: VcpuState::new(entry),
            running: core::sync::atomic::AtomicBool::new(false),
            guest,
            id: cpuid,
            interrupts: irq,
        })
    }
}

pub use runvm::{VMMContext, VMMContextPriv};

#[derive(Debug)]
pub struct InterruptState {
    timer_expire: AtomicU64,
    has_external_interrupt: AtomicBool,
    has_software_interrupt: AtomicBool,
}
impl InterruptState {
    pub fn new() -> Self {
        InterruptState {
            timer_expire: AtomicU64::new(!0),
            has_external_interrupt: AtomicBool::new(false),
            has_software_interrupt: AtomicBool::new(false),
        }
    }
}

#[cfg(target_arch = "riscv64")]
pub fn get_cycle() -> u64 {
    time::read() as u64
}

#[cfg(target_arch = "riscv32")]
pub fn get_cycle() -> u64 {
    loop {
        let hi = timeh::read();
        let lo = time::read();
        let tmp = timeh::read();
        if hi == tmp {
            return ((hi as u64) << 32) | (lo as u64);
        }
    }
}

impl InterruptState {
    pub fn has_timer_expired(&self) -> bool {
        let now = get_cycle();
        return now >= self.timer_expire.load(Ordering::Relaxed);
    }
    pub fn set_timer(&self, time: u64) {
        self.timer_expire.store(time, Ordering::Relaxed);
    }
    pub fn set_software_interrupt(&self, x: bool) {
        self.has_software_interrupt.store(x, Ordering::Relaxed);
    }
    pub fn set_external_interrupt(&self, x: bool) {
        self.has_external_interrupt.store(x, Ordering::Relaxed);
    }
    fn apply(&self) {
        let mut ints = hvip::read();
        ints.set_vssip(self.has_software_interrupt.load(Ordering::Relaxed));
        ints.set_vseip(self.has_external_interrupt.load(Ordering::Relaxed));
        ints.set_vstip(self.has_timer_expired());
        unsafe { ints.write() };
    }
}
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VcpuState {
    pub ctx: VMMContext,
    pub privctx: VMMContextPriv,
}

impl VcpuState {
    pub fn new(entry: u64) -> Self {
        let mut ctx = VMMContext::default();
        ctx.sepc = entry as usize;
        ctx.sstatus = riscv::register::sstatus::read().bits();
        ctx.sstatus |= 1 << 8; // spp.
        VcpuState {
            ctx,
            privctx: VMMContextPriv::default(),
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct VcpuIo {
    // ?
}

mod decode;
mod pseudoinsn;
mod runvm;
pub mod sbi;
mod traps;
