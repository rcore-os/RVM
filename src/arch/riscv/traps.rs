//! Trap handler crate.
use super::runvm::*;
use riscv::register::*;
pub fn get_cause(cause: usize) -> (usize, bool) {
    let msb = {
        let x = !0usize;
        x ^ (x >> 1)
    };
    let cause_id = cause & !msb;
    let is_interrupt = (cause & msb) != 0;
    (cause_id, is_interrupt)
}
pub fn get_trap_address(tvec: usize, cause: usize) -> Option<usize> {
    let flag = tvec & 3;
    let base = tvec - flag;
    if flag == 0 {
        return Some(base); // direct
    } else if flag == 1 {
        let (cause_id, is_interrupt) = get_cause(cause);
        if is_interrupt {
            Some(base + 4 * cause_id)
        } else {
            Some(base)
        }
    } else {
        return None;
    }
}
pub fn pass_down_exception(ctx: &mut VMMContext, cause: usize, tval: usize) {
    // downgrade a specific exception. for example, downgrade VirtualInstruction to IllegalInstruction.
    let tvec = vstvec::read().bits();
    let trap_handler_pc = get_trap_address(tvec, cause).unwrap_or(tvec);
    let old_pc = ctx.sepc;
    ctx.sepc = trap_handler_pc;
    vsepc::write(old_pc);
    unsafe { vscause::Vscause::from_bits(cause).write() };
    let previous_spp = sstatus::read().spp();
    match previous_spp {
        sstatus::SPP::Supervisor => unsafe {
            vsstatus::set_spp();
        },
        sstatus::SPP::User => unsafe {
            vsstatus::clear_spp();
        },
    }
    let mut status = vsstatus::read();
    status.set_spie(status.sie());
    status.set_sie(false);
    unsafe {
        status.write();
    }
    vstval::write(tval);
}

pub fn init_traps() {
    // Delegate every single exception...
    let mut del = hedeleg::read();
    del.set_ex0(true);
    del.set_ex1(true);
    del.set_ex2(true);
    del.set_ex3(true);
    del.set_ex4(true);
    del.set_ex5(true);
    del.set_ex6(true);
    del.set_ex7(true);
    del.set_ex8(true);
    del.set_ex12(true);
    del.set_ex13(true);
    del.set_ex15(true);
    // ... and interrupt.
    let mut del2 = hideleg::read();
    del2.set_eip(true);
    del2.set_sip(true);
    del2.set_tip(true);
    unsafe {
        del.write();
        del2.write();
    }
    // enable hcounteren.
    /*
    unsafe {
        hcounteren::set_cy();
        hcounteren::set_tm();
        hcounteren::set_ir();
    }*/
    // well qemu does not support these flags.
}
