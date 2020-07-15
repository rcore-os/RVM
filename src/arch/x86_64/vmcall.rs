use core::convert::TryFrom;
use numeric_enum_macro::numeric_enum;

numeric_enum! {
    #[repr(u64)]
    #[derive(Debug)]
    enum VmcallNum {
        ClockPairing = 9,
    }
}

#[repr(i64)]
#[derive(Debug)]
#[allow(dead_code)]
pub enum VmcallStatus {
    Ok = 0,
    NotPermitted = -1,
    Fault = -14,
    NotSupported = -95,
    UnknownHypercall = -1000,
}

pub fn vmcall(num: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> VmcallStatus {
    match VmcallNum::try_from(num) {
        Ok(num) => match num {
            VmcallNum::ClockPairing => VmcallStatus::NotSupported,
        },
        Err(num) => {
            info!(
                "[RVM] Unknown hypercall {:?} (arg0={:#x?}, arg1={:#x?}, arg2={:#x?}, arg3={:#x?})",
                num, a0, a1, a2, a3
            );
            VmcallStatus::UnknownHypercall
        }
    }
}
