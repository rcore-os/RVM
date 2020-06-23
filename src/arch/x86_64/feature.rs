#![allow(dead_code)]

use super::vcpu::GuestState;
use alloc::vec::Vec;
use bit_field::BitField;
use core::convert::TryFrom;
use lazy_static::lazy_static;
use numeric_enum_macro::numeric_enum;
use raw_cpuid::CpuIdResult;

pub fn cpuid(sel: u32, guest_state: &mut GuestState) {
    let res = raw_cpuid::cpuid!(sel);
    guest_state.rax = res.eax as u64;
    guest_state.rbx = res.ebx as u64;
    guest_state.rcx = res.ecx as u64;
    guest_state.rdx = res.edx as u64;
}

pub fn cpuid_c(sel: u32, sel_c: u32, guest_state: &mut GuestState) {
    let res = raw_cpuid::cpuid!(sel, sel_c);
    guest_state.rax = res.eax as u64;
    guest_state.rbx = res.ebx as u64;
    guest_state.rcx = res.ecx as u64;
    guest_state.rdx = res.edx as u64;
}

pub const MAX_SUPPORTED_CPUID: u32 = 0x17;
pub const MAX_SUPPORTED_CPUID_HYP: u32 = 0x40000001;
pub const MAX_SUPPORTED_CPUID_EXT: u32 = 0x8000001e;

numeric_enum! {
#[repr(u32)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub enum X86CpuidLeafNum {
    BASE = 0,
    MODEL_FEATURES = 0x1,
    CACHE_V1 = 0x2,
    CACHE_V2 = 0x4,
    MON = 0x5,
    THERMAL_AND_POWER = 0x6,
    EXTENDED_FEATURE_FLAGS = 0x7,
    PERFORMANCE_MONITORING = 0xa,
    TOPOLOGY = 0xb,
    XSAVE = 0xd,
    PT = 0x14,
    TSC = 0x15,

    HYP_BASE = 0x40000000,
    // HYP_VENDOR = 0x40000000,
    KVM_FEATURES = 0x40000001,

    EXT_BASE = 0x80000000,
    BRAND = 0x80000002,
    ADDR_WIDTH = 0x80000008,
    AMD_TOPOLOGY = 0x8000001e,
}
}

#[derive(Clone, Copy, Debug)]
pub struct X86CpuidBit {
    pub leaf_num: u32,
    pub word: u8,
    pub bit: usize,
}

impl X86CpuidBit {
    const fn from(leaf: u32, word: u8, bit: usize) -> Self {
        X86CpuidBit {
            leaf_num: leaf,
            word,
            bit,
        }
    }
}

/* cpu vendors */
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
enum X86Vendor {
    UNKNOWN,
    INTEL,
    AMD,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct X86ModelInfo {
    family: u8,
    model: u8,
    stepping: u8,
    display_family: u32,
    display_model: u32,
    patch_level: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[allow(non_camel_case_types)]
enum X86Microarch {
    UNKNOWN,
    INTEL_NEHALEM,
    INTEL_WESTMERE,
    INTEL_SANDY_BRIDGE,
    INTEL_IVY_BRIDGE,
    INTEL_BROADWELL,
    INTEL_HASWELL,
    INTEL_SKYLAKE,
    INTEL_KABYLAKE,
    INTEL_SILVERMONT, // Silvermont, Airmont
    INTEL_GOLDMONT,   // Goldmont, Goldmont+
    AMD_BULLDOZER,
    AMD_JAGUAR,
    AMD_ZEN,
}

lazy_static! {
    static ref X86_FEATURE: X86Feature = X86Feature::new();
}

struct X86Feature {
    cpuid: Vec<CpuIdResult>,
    cpuid_hyp: Vec<CpuIdResult>,
    cpuid_ext: Vec<CpuIdResult>,
    max_cpuid: u32,
    max_hyp_cpuid: u32,
    max_ext_cpuid: u32,
    vendor: X86Vendor,
    model_info: X86ModelInfo,
    microarch: X86Microarch,
}

impl X86Feature {
    fn new() -> Self {
        /* figure out the vendor */
        let vendor = match raw_cpuid::CpuId::new()
            .get_vendor_info()
            .unwrap()
            .as_string()
        {
            "GenuineIntel" => X86Vendor::INTEL,
            "AuthenticAMD" => X86Vendor::AMD,
            _ => X86Vendor::UNKNOWN,
        };
        info!("[RVM] X86 VENDOR is {:?}", vendor);

        /* test for cpuid count */
        let max_cpuid = raw_cpuid::cpuid!(0).eax.min(MAX_SUPPORTED_CPUID);
        let max_ext_cpuid = raw_cpuid::cpuid!(X86CpuidLeafNum::EXT_BASE)
            .eax
            .min(MAX_SUPPORTED_CPUID_EXT);
        let max_hyp_cpuid = raw_cpuid::cpuid!(X86CpuidLeafNum::HYP_BASE)
            .eax
            .min(MAX_SUPPORTED_CPUID_HYP);
        info!("[RVM] max cpuid {:#x}", max_cpuid);
        info!("[RVM] max extended cpuid {:#x}", max_ext_cpuid);
        info!("[RVM] max hypervisor cpuid {:#x}", max_hyp_cpuid);

        /* read in the cpuids */
        let cpuid = (0..=max_cpuid).map(|i| raw_cpuid::cpuid!(i, 0)).collect();
        let cpuid_ext = (X86CpuidLeafNum::EXT_BASE as u32..=max_ext_cpuid)
            .map(|i| raw_cpuid::cpuid!(i, 0))
            .collect();
        let cpuid_hyp = (X86CpuidLeafNum::HYP_BASE as u32..=max_hyp_cpuid)
            .map(|i| raw_cpuid::cpuid!(i, 0))
            .collect();

        /* populate the model info */
        let feature_info = raw_cpuid::CpuId::new().get_feature_info().unwrap();
        let mut model_info = X86ModelInfo {
            family: feature_info.family_id(),
            model: feature_info.model_id(),
            stepping: feature_info.stepping_id(),
            display_family: feature_info.family_id() as u32,
            display_model: feature_info.model_id() as u32,
            patch_level: match vendor {
                X86Vendor::INTEL => x86_intel_get_patch_level(),
                X86Vendor::AMD => x86_amd_get_patch_level(),
                _ => 0,
            },
        };
        if model_info.family == 0xf {
            model_info.display_family += feature_info.extended_family_id() as u32;
        }
        if model_info.family == 0xf || model_info.family == 0x6 {
            model_info.display_model += (feature_info.extended_model_id() as u32) << 4;
        }
        let microarch = model_info.get_microarch(vendor);

        // x86_microarch_config = select_microarch_config(x86_microarch); // FIXME

        // FIXME some codes left
        info!("[RVM] success init features");
        X86Feature {
            cpuid,
            cpuid_hyp,
            cpuid_ext,
            max_cpuid,
            max_hyp_cpuid,
            max_ext_cpuid,
            vendor,
            model_info,
            microarch,
        }
    }

    fn cpuid(&self, leaf: X86CpuidLeafNum) -> Option<CpuIdResult> {
        let leaf = leaf as u32;
        if leaf < X86CpuidLeafNum::HYP_BASE as u32 {
            self.cpuid.get(leaf as usize).cloned()
        } else if leaf < X86CpuidLeafNum::EXT_BASE as u32 {
            self.cpuid_hyp
                .get((leaf - X86CpuidLeafNum::HYP_BASE as u32) as usize)
                .cloned()
        } else {
            self.cpuid_ext
                .get((leaf - X86CpuidLeafNum::EXT_BASE as u32) as usize)
                .cloned()
        }
    }

    fn feature_test(&self, bit: X86CpuidBit) -> bool {
        assert!(bit.word <= 3 && bit.bit <= 31);
        let leaf = self
            .cpuid(X86CpuidLeafNum::try_from(bit.leaf_num).unwrap())
            .unwrap();
        match bit.word {
            0 => leaf.eax,
            1 => leaf.ebx,
            2 => leaf.ecx,
            3 => leaf.edx,
            _ => return false,
        }
        .get_bit(bit.bit)
    }
}

impl X86ModelInfo {
    fn get_microarch(&self, vendor: X86Vendor) -> X86Microarch {
        if vendor == X86Vendor::INTEL && self.family == 0x6 {
            match self.display_model {
                0x1a | 0x1e | 0x1f | 0x2e /* Nehalem */ =>
                    X86Microarch::INTEL_NEHALEM,
                0x25 | 0x2c | 0x2f /* Westmere */ =>
                    X86Microarch::INTEL_WESTMERE,
                0x2a| /* Sandy Bridge */
                0x2d /* Sandy Bridge EP */ =>
                    X86Microarch::INTEL_SANDY_BRIDGE,
                0x3a| /* Ivy Bridge */
                0x3e /* Ivy Bridge EP */ =>
                    X86Microarch::INTEL_IVY_BRIDGE,
                0x3c| /* Haswell DT */
                0x3f| /* Haswell MB */
                0x45| /* Haswell ULT */
                0x46 /* Haswell ULX */ =>
                    X86Microarch::INTEL_HASWELL,
                0x3d| /* Broadwell */
                0x47| /* Broadwell H */
                0x56| /* Broadwell EP */
                0x4f /* Broadwell EX */ =>
                    X86Microarch::INTEL_BROADWELL,
                0x4e| /* Skylake Y/U */
                0x5e| /* Skylake H/S */
                0x55 /* Skylake E */ =>
                    X86Microarch::INTEL_SKYLAKE,
                0x8e| /* Kabylake Y/U */
                0x9e /* Kabylake H/S */ =>
                    X86Microarch::INTEL_KABYLAKE,
                0x37| /* Silvermont */
                0x4a| /* Silvermont "Cherry View" */
                0x4d| /* Silvermont "Avoton" */
                0x4c| /* Airmont "Braswell" */
                0x5a /* Airmont */ =>
                    X86Microarch::INTEL_SILVERMONT,
                0x5c /* Goldmont */ =>
                    X86Microarch::INTEL_GOLDMONT,
                _ => X86Microarch::UNKNOWN
            }
        } else if vendor == X86Vendor::AMD && self.family == 0xf {
            match self.display_family { // zen
                0x15 /* Bulldozer */ =>
                    X86Microarch::AMD_BULLDOZER,
                0x16 /* Jaguar */ =>
                    X86Microarch::AMD_JAGUAR,
                0x17 /* Zen */ =>
                    X86Microarch::AMD_ZEN,
                _ => X86Microarch::UNKNOWN
            }
        } else {
            X86Microarch::UNKNOWN
        }
    }
}

fn x86_intel_get_patch_level() -> u32 {
    warn!("[RVM] running unimplemented fn x86_intel_get_patch_level");
    0
}

fn x86_amd_get_patch_level() -> u32 {
    warn!("[RVM] running unimplemented fn x86_amd_get_patch_level");
    0
}

/* add feature bits to test here */
/* format: X86_CPUID_BIT(cpuid leaf, register (eax-edx:0-3), bit) */
pub const X86_FEATURE_SSE3: X86CpuidBit = X86CpuidBit::from(0x1, 2, 0);
pub const X86_FEATURE_MON: X86CpuidBit = X86CpuidBit::from(0x1, 2, 3);
pub const X86_FEATURE_VMX: X86CpuidBit = X86CpuidBit::from(0x1, 2, 5);
pub const X86_FEATURE_TM2: X86CpuidBit = X86CpuidBit::from(0x1, 2, 8);
pub const X86_FEATURE_SSSE3: X86CpuidBit = X86CpuidBit::from(0x1, 2, 9);
pub const X86_FEATURE_PDCM: X86CpuidBit = X86CpuidBit::from(0x1, 2, 15);
pub const X86_FEATURE_PCID: X86CpuidBit = X86CpuidBit::from(0x1, 2, 17);
pub const X86_FEATURE_SSE4_1: X86CpuidBit = X86CpuidBit::from(0x1, 2, 19);
pub const X86_FEATURE_SSE4_2: X86CpuidBit = X86CpuidBit::from(0x1, 2, 20);
pub const X86_FEATURE_X2APIC: X86CpuidBit = X86CpuidBit::from(0x1, 2, 21);
pub const X86_FEATURE_TSC_DEADLINE: X86CpuidBit = X86CpuidBit::from(0x1, 2, 24);
pub const X86_FEATURE_AESNI: X86CpuidBit = X86CpuidBit::from(0x1, 2, 25);
pub const X86_FEATURE_XSAVE: X86CpuidBit = X86CpuidBit::from(0x1, 2, 26);
pub const X86_FEATURE_AVX: X86CpuidBit = X86CpuidBit::from(0x1, 2, 28);
pub const X86_FEATURE_RDRAND: X86CpuidBit = X86CpuidBit::from(0x1, 2, 30);
pub const X86_FEATURE_HYPERVISOR: X86CpuidBit = X86CpuidBit::from(0x1, 2, 31);
pub const X86_FEATURE_FPU: X86CpuidBit = X86CpuidBit::from(0x1, 3, 0);
pub const X86_FEATURE_SEP: X86CpuidBit = X86CpuidBit::from(0x1, 3, 11);
pub const X86_FEATURE_CLFLUSH: X86CpuidBit = X86CpuidBit::from(0x1, 3, 19);
pub const X86_FEATURE_ACPI: X86CpuidBit = X86CpuidBit::from(0x1, 3, 22);
pub const X86_FEATURE_MMX: X86CpuidBit = X86CpuidBit::from(0x1, 3, 23);
pub const X86_FEATURE_FXSR: X86CpuidBit = X86CpuidBit::from(0x1, 3, 24);
pub const X86_FEATURE_SSE: X86CpuidBit = X86CpuidBit::from(0x1, 3, 25);
pub const X86_FEATURE_SSE2: X86CpuidBit = X86CpuidBit::from(0x1, 3, 26);
pub const X86_FEATURE_TM: X86CpuidBit = X86CpuidBit::from(0x1, 3, 29);
pub const X86_FEATURE_DTS: X86CpuidBit = X86CpuidBit::from(0x6, 0, 0);
pub const X86_FEATURE_PLN: X86CpuidBit = X86CpuidBit::from(0x6, 0, 4);
pub const X86_FEATURE_PTM: X86CpuidBit = X86CpuidBit::from(0x6, 0, 6);
pub const X86_FEATURE_HWP: X86CpuidBit = X86CpuidBit::from(0x6, 0, 7);
pub const X86_FEATURE_HWP_NOT: X86CpuidBit = X86CpuidBit::from(0x6, 0, 8);
pub const X86_FEATURE_HWP_ACT: X86CpuidBit = X86CpuidBit::from(0x6, 0, 9);
pub const X86_FEATURE_HWP_PREF: X86CpuidBit = X86CpuidBit::from(0x6, 0, 10);
pub const X86_FEATURE_HW_FEEDBACK: X86CpuidBit = X86CpuidBit::from(0x6, 2, 0);
pub const X86_FEATURE_PERF_BIAS: X86CpuidBit = X86CpuidBit::from(0x6, 2, 3);
pub const X86_FEATURE_FSGSBASE: X86CpuidBit = X86CpuidBit::from(0x7, 1, 0);
pub const X86_FEATURE_TSC_ADJUST: X86CpuidBit = X86CpuidBit::from(0x7, 1, 1);
pub const X86_FEATURE_AVX2: X86CpuidBit = X86CpuidBit::from(0x7, 1, 5);
pub const X86_FEATURE_SMEP: X86CpuidBit = X86CpuidBit::from(0x7, 1, 7);
pub const X86_FEATURE_ERMS: X86CpuidBit = X86CpuidBit::from(0x7, 1, 9);
pub const X86_FEATURE_INVPCID: X86CpuidBit = X86CpuidBit::from(0x7, 1, 10);
pub const X86_FEATURE_RDSEED: X86CpuidBit = X86CpuidBit::from(0x7, 1, 18);
pub const X86_FEATURE_SMAP: X86CpuidBit = X86CpuidBit::from(0x7, 1, 20);
pub const X86_FEATURE_CLFLUSHOPT: X86CpuidBit = X86CpuidBit::from(0x7, 1, 23);
pub const X86_FEATURE_CLWB: X86CpuidBit = X86CpuidBit::from(0x7, 1, 24);
pub const X86_FEATURE_PT: X86CpuidBit = X86CpuidBit::from(0x7, 1, 25);
pub const X86_FEATURE_UMIP: X86CpuidBit = X86CpuidBit::from(0x7, 2, 2);
pub const X86_FEATURE_PKU: X86CpuidBit = X86CpuidBit::from(0x7, 2, 3);
pub const X86_FEATURE_MD_CLEAR: X86CpuidBit = X86CpuidBit::from(0x7, 3, 10);
pub const X86_FEATURE_IBRS_IBPB: X86CpuidBit = X86CpuidBit::from(0x7, 3, 26);
pub const X86_FEATURE_STIBP: X86CpuidBit = X86CpuidBit::from(0x7, 3, 27);
pub const X86_FEATURE_L1D_FLUSH: X86CpuidBit = X86CpuidBit::from(0x7, 3, 28);
pub const X86_FEATURE_ARCH_CAPABILITIES: X86CpuidBit = X86CpuidBit::from(0x7, 3, 29);
pub const X86_FEATURE_SSBD: X86CpuidBit = X86CpuidBit::from(0x7, 3, 31);

pub const X86_FEATURE_KVM_PVCLOCK_STABLE: X86CpuidBit = X86CpuidBit::from(0x40000001, 0, 24);
pub const X86_FEATURE_AMD_TOPO: X86CpuidBit = X86CpuidBit::from(0x80000001, 2, 22);
pub const X86_FEATURE_SYSCALL: X86CpuidBit = X86CpuidBit::from(0x80000001, 3, 11);
pub const X86_FEATURE_NX: X86CpuidBit = X86CpuidBit::from(0x80000001, 3, 20);
pub const X86_FEATURE_HUGE_PAGE: X86CpuidBit = X86CpuidBit::from(0x80000001, 3, 26);
pub const X86_FEATURE_RDTSCP: X86CpuidBit = X86CpuidBit::from(0x80000001, 3, 27);
pub const X86_FEATURE_INVAR_TSC: X86CpuidBit = X86CpuidBit::from(0x80000007, 3, 8);
