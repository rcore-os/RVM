pub struct SBIRet<'a> {
    pub error: &'a mut usize,
    pub value: &'a mut usize,
}
impl<'a> SBIRet<'a> {
    pub fn new(ctx: &'a mut super::VMMContext) -> Self {
        SBIRet {
            error: &mut ctx.a0,
            value: &mut ctx.a1,
        }
    }
}
pub enum SBICall<'a> {
    SetTimer {
        time_value: u64,
    },
    LegacyConsolePutchar {
        ch: u32,
    },
    LegacyConsoleGetchar {
        chr: &'a mut usize,
    },
    GetSpecVersion(SBIRet<'a>),
    GetSBIImplID(SBIRet<'a>),
    GetImplVersion(SBIRet<'a>),
    ProbeExtension(usize, SBIRet<'a>),
    GetVendorID(SBIRet<'a>),
    GetArchID(SBIRet<'a>),
    GetMachineImplID(SBIRet<'a>),
    Unknown {
        eid: i32,
        fid: i32,
        arg0: usize,
        arg1: usize,
        arg2: usize,
        arg3: usize,
    },
}
use SBICall::*;
pub const SBI_EID_TIME: i32 = 0x54494D45;
pub const SBI_FID_TIME_SET: i32 = 0;

pub const SBI_EID_BASE: i32 = 0x10;
pub const SBI_FID_GET_SPEC_VERSION: i32 = 0;
pub const SBI_FID_GET_IMPL_ID: i32 = 1;
pub const SBI_FID_GET_IMPL_VERSION: i32 = 2;
pub const SBI_FID_PROBE_EXTENSION: i32 = 3;
pub const SBI_FID_GET_MVENDOR_ID: i32 = 4;
pub const SBI_FID_GET_MARCHID: i32 = 5;
pub const SBI_FID_GET_MIMPID: i32 = 6;

pub const SBI_SET_TIMER: i32 = 0;
pub const SBI_CONSOLE_PUTCHAR: i32 = 1;
pub const SBI_CONSOLE_GETCHAR: i32 = 2;
pub const SBI_CLEAR_IPI: i32 = 3;
pub const SBI_SEND_IPI: i32 = 4;
pub const SBI_REMOTE_FENCE_I: i32 = 5;
pub const SBI_REMOTE_SFENCE_VMA: i32 = 6;
pub const SBI_REMOTE_SFENCE_VMA_ASID: i32 = 7;
pub const SBI_SHUTDOWN: i32 = 8;

#[cfg(target_arch = "riscv64")]
fn get_first_u64_arg(ctx: &mut super::VMMContext) -> u64 {
    ctx.a0 as u64
}
#[cfg(target_arch = "riscv32")]
fn get_first_u64_arg(ctx: &mut super::VMMContext) -> u64 {
    let ret = (ctx.a1 as u64) << 32;
    ret | (ctx.a0 as u64)
}

pub fn try_handle_sbi_call<'a>(ctx: &'a mut super::VMMContext) -> SBICall<'a> {
    match (ctx.a7 as i32, ctx.a6 as i32) {
        (self::SBI_EID_TIME, self::SBI_FID_TIME_SET) => SetTimer {
            time_value: get_first_u64_arg(ctx),
        },
        (self::SBI_SET_TIMER, _) => SetTimer {
            time_value: get_first_u64_arg(ctx),
        },
        (self::SBI_EID_BASE, self::SBI_FID_GET_SPEC_VERSION) => GetSpecVersion(SBIRet::new(ctx)),
        (self::SBI_EID_BASE, self::SBI_FID_GET_IMPL_ID) => GetSBIImplID(SBIRet::new(ctx)),
        (self::SBI_EID_BASE, self::SBI_FID_GET_IMPL_VERSION) => GetImplVersion(SBIRet::new(ctx)),
        (self::SBI_EID_BASE, self::SBI_FID_PROBE_EXTENSION) => {
            ProbeExtension(ctx.a0, SBIRet::new(ctx))
        }
        (self::SBI_EID_BASE, self::SBI_FID_GET_MVENDOR_ID) => GetVendorID(SBIRet::new(ctx)),
        (self::SBI_EID_BASE, self::SBI_FID_GET_MARCHID) => GetArchID(SBIRet::new(ctx)),
        (self::SBI_EID_BASE, self::SBI_FID_GET_MIMPID) => GetMachineImplID(SBIRet::new(ctx)),
        (eid, fid) => Unknown {
            eid,
            fid,
            arg0: ctx.a0,
            arg1: ctx.a1,
            arg2: ctx.a2,
            arg3: ctx.a3,
        },
    }
}
