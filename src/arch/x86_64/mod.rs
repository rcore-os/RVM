#![allow(clippy::unnecessary_wraps)]

use raw_cpuid::CpuId;

mod consts;
mod ept;
mod feature;
mod guest;
mod msr;
mod structs;
mod timer;
mod utils;
mod vcpu;
mod vmcall;
mod vmcs;
mod vmexit;

pub use ept::EPageTable as ArchRvmPageTable;
pub use guest::Guest;
pub use vcpu::Vcpu;

pub fn check_hypervisor_feature() -> bool {
    if let Some(feature) = CpuId::new().get_feature_info() {
        feature.has_vmx()
    } else {
        false
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct VcpuIo {
    pub access_size: u8,
    pub _padding1: [u8; 3],
    pub data: [u8; 4],
}
