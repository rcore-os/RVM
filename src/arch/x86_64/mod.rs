use raw_cpuid::CpuId;

mod consts;
mod defines;
mod ept;
mod feature;
mod guest;
mod msr;
mod structs;
mod timer;
pub mod vcpu;
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
