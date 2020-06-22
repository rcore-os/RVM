use raw_cpuid::CpuId;

mod consts;
mod epage_table;
mod exit_reason;
mod feature;
mod guest;
mod msr;
mod structs;
mod timer;
mod vcpu;
mod vmcs;
mod vmexit;

pub use guest::Guest;
pub use vcpu::Vcpu;

fn check_hypervisor_feature() -> bool {
    if let Some(feature) = CpuId::new().get_feature_info() {
        feature.has_vmx()
    } else {
        false
    }
}
