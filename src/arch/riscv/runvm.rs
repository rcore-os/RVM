//! Mocks a sysenter and sysexit pair, as well as handling necessary interrupts.

use log::*;

use riscv::register::*;
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct VMMContextPriv {
    pub vsstatus: usize,
    pub vsie: usize,
    pub vstvec: usize,
    pub vsscratch: usize,
    pub vsepc: usize,
    pub vscause: usize,
    pub vstval: usize,
    pub vsatp: usize,
}

pub struct VMMContextPrivGuard<'a> {
    ctx: &'a mut VMMContextPriv,
}

impl<'a> Drop for VMMContextPrivGuard<'a> {
    fn drop(&mut self) {
        *self.ctx = VMMContextPriv::dump();
    }
}

impl VMMContextPriv {
    /*
    pub fn load<'a>(&'a mut self) -> VMMContextPrivGuard<'a> {
        self.restore();
        VMMContextPrivGuard { ctx: self }
    }
    */
    pub fn dump() -> Self {
        VMMContextPriv {
            vsstatus: vsstatus::read().bits(),
            vsie: vsie::read().bits(),
            vstvec: vstvec::read().bits(),
            vsscratch: vsscratch::read(),
            vsepc: vsepc::read(),
            vscause: vscause::read().bits(),
            vstval: vstval::read(),
            vsatp: vsatp::read().bits(),
        }
    }
    pub fn restore(self) {
        use riscv::register::*;
        unsafe {
            vsstatus::Vsstatus::from_bits(self.vsstatus).write();
            vsie::Vsie::from_bits(self.vsie).write();
            vstvec::Vstvec::from_bits(self.vstvec).write();
            vsscratch::write(self.vsscratch);
            vsepc::write(self.vsepc);
            vscause::Vscause::from_bits(self.vscause).write();
            vstval::write(self.vstval);
            vsatp::Vsatp::from_bits(self.vsatp).write();
        }
    }
}
pub unsafe fn resume_vm(ctx: &mut VMMContext) {
    // disable host interrupt.
    let sie = riscv::register::sstatus::read().sie();
    riscv::register::sstatus::clear_sie();
    riscv::register::hstatus::set_spv();
    // backup trap handler.
    let stvec = riscv::register::stvec::read();
    riscv::register::stvec::write(
        vm_trap_entry as usize,
        riscv::register::stvec::TrapMode::Direct,
    );
    // Let's go.
    info!("[rvm] Entering VM.");
    run_vm(ctx as *mut _);
    // We're back.
    info!("[rvm] Back from VM.");
    // set trap handler.
    riscv::register::stvec::write(stvec.address(), stvec.trap_mode().unwrap());
    riscv::register::hstatus::clear_spv();
    // enable interrupt.
    if sie {
        riscv::register::sstatus::set_sie();
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct VMMContext {
    pub sp_kernel: usize,
    pub ra: usize,
    pub sp: usize,
    pub gp: usize,
    pub tp: usize,
    pub t0: usize,
    pub t1: usize,
    pub t2: usize,
    pub s0: usize,
    pub s1: usize,
    pub a0: usize,
    pub a1: usize,
    pub a2: usize,
    pub a3: usize,
    pub a4: usize,
    pub a5: usize,
    pub a6: usize,
    pub a7: usize,
    pub s2: usize,
    pub s3: usize,
    pub s4: usize,
    pub s5: usize,
    pub s6: usize,
    pub s7: usize,
    pub s8: usize,
    pub s9: usize,
    pub s10: usize,
    pub s11: usize,
    pub t3: usize,
    pub t4: usize,
    pub t5: usize,
    pub t6: usize,
    pub sstatus: usize,
    pub sepc: usize,
}

impl VMMContext {
    pub fn get(&self, reg: u8) -> usize {
        match reg {
            0 => 0,
            1 => self.ra,
            2 => self.sp,
            3 => self.gp,
            4 => self.tp,
            5 => self.t0,
            6 => self.t1,
            7 => self.t2,
            8 => self.s0,
            9 => self.s1,
            10 => self.a0,
            11 => self.a1,
            12 => self.a2,
            13 => self.a3,
            14 => self.a4,
            15 => self.a5,
            16 => self.a6,
            17 => self.a7,
            18 => self.s2,
            19 => self.s3,
            20 => self.s4,
            21 => self.s5,
            22 => self.s6,
            23 => self.s7,
            24 => self.s8,
            25 => self.s9,
            26 => self.s10,
            27 => self.s11,
            28 => self.t3,
            29 => self.t4,
            30 => self.t5,
            31 => self.t6,
            _ => panic!("bad reg id."),
        }
    }
}

#[cfg(target_arch = "riscv32")]
global_asm!(
    r"
    .equ XLENB, 4
    .macro LOAD_SP a1, a2
        lw \a1, \a2*XLENB(sp)
    .endm
    .macro STORE_SP a1, a2
        sw \a1, \a2*XLENB(sp)
    .endm
"
);
#[cfg(target_arch = "riscv64")]
global_asm!(
    r"
    .equ XLENB, 8
    .macro LOAD_SP a1, a2
        ld \a1, \a2*XLENB(sp)
    .endm
    .macro STORE_SP a1, a2
        sd \a1, \a2*XLENB(sp)
    .endm
"
);

global_asm!(include_str!("vmtrap.S"));

#[allow(improper_ctypes)]
extern "C" {
    fn vm_trap_entry();
    fn run_vm(regs: *mut VMMContext);
}
