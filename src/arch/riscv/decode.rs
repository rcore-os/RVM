//! Decode riscv instructions, only for load/store.
//! Note that only general registers are supported. No float registers.
use bit_field::*;
#[derive(Debug, Copy, Clone)]
pub struct MemOp {
    pub access_size: u8,
    pub is_store: bool,
    pub src: u8, // for read.
    pub dst: u8, // for write.
    pub is_rvc: bool,
    pub sign_extension: bool,
}
fn transform_general_reg(r: u8) -> u8 {
    if r <= 7 {
        return r + 8;
    }
    unreachable!()
}
enum RVLS {
    Load { rd: u8, access_size: u8 },
    Store { rs2: u8, access_size: u8 },
}
use RVLS::*;
fn parse_rvc_mem(insn: u16) -> Option<RVLS> {
    let r = |hi: usize, lo: usize| insn.get_bits(lo..(hi + 1)) as usize;
    if r(1, 0) == 0b10 {
        let rd = r(11, 7) as u8;
        //let rs1 = rd;
        let rs2 = r(6, 2) as u8;

        return match r(15, 13) {
            0b010 if rd != 0 => Some(Load { rd, access_size: 4 }),
            0b011 if rd != 0 => Some(Load { rd, access_size: 8 }),
            0b110 => Some(Store {
                rs2,
                access_size: 4,
            }),
            0b111 => Some(Store {
                rs2,
                access_size: 8,
            }),
            _ => None,
        };
    }
    if r(1, 0) == 0b00 {
        //let rs1 = transform_general_reg(r(9,7) as u8);
        let rs2 = transform_general_reg(r(4, 2) as u8);
        //let rs = rs1;
        let rd = rs2;
        return match r(15, 13) {
            0b010 => Some(Load { rd, access_size: 4 }),
            0b011 => Some(Load { rd, access_size: 8 }),
            0b110 => Some(Store {
                rs2,
                access_size: 4,
            }),
            0b111 => Some(Store {
                rs2,
                access_size: 8,
            }),
            _ => None,
        };
    }
    None
}

// Some(Some(op)) for success, Some(None) for please-try-rvi, and None for unknown rvc.
pub fn decode_memory_ops_rvc(insn: u16) -> Option<Option<MemOp>> {
    if insn.get_bits(0..2) == 0b00 {
        match parse_rvc_mem(insn)? {
            Load { rd, access_size } => Some(Some(MemOp {
                is_store: false,
                access_size,
                dst: rd,
                is_rvc: true,
                src: 0,
                sign_extension: true,
            })),
            Store { rs2, access_size } => Some(Some(MemOp {
                is_store: true,
                access_size,
                src: rs2,
                is_rvc: true,
                dst: 0,
                sign_extension: true,
            })),
        }
    } else {
        Some(None)
    }
}

pub fn decode_memory_ops_rvi(insn: u32) -> Option<MemOp> {
    let opcode = insn.get_bits(0..7);
    //let funct = insn.get_bits(12..15);
    //let rs1 = insn.get_bits(15..20);
    let rd = insn.get_bits(7..12) as u8;
    let rs2 = insn.get_bits(20..25) as u8;
    let access_size = match insn.get_bits(12..14) {
        0b00 => 1,
        0b01 => 2,
        0b10 => 4,
        0b11 => 8,
        _ => unreachable!(),
    };
    if opcode == 0b0000011 {
        // load
        let sign_extension = !insn.get_bit(14);
        return Some(MemOp {
            is_store: false,
            access_size,
            dst: rd,
            is_rvc: false,
            src: 0,
            sign_extension,
        });
    } else if insn.get_bits(0..7) == 0b0100011 {
        if !insn.get_bit(14) {
            return Some(MemOp {
                is_store: false,
                access_size,
                src: rs2,
                is_rvc: false,
                dst: 0,
                sign_extension: false,
            });
        }
    }
    None
}

pub fn load_half(epc: usize) -> u16 {
    (unsafe { riscv::asm::hlvx_hu(epc) }) as u16
}
pub fn load_word(epc: usize) -> u32 {
    (load_half(epc) as u32) | ((load_half(epc + 2) as u32) << 16)
}

pub enum Insn {
    C(u16),
    I(u32),
}
pub use Insn::*;
pub fn read_instruction(epc: usize) -> Option<Insn> {
    let insn_16 = load_half(epc);
    if insn_16 & 0b11 == 0b00 {
        Some(C(insn_16))
    } else if insn_16 & 0b11 == 0b11 {
        let insn_32 = load_word(epc);
        Some(I(insn_32))
    } else {
        error!("bad instruction: at epc {:x}: {}", epc, insn_16);
        None
    }
}
