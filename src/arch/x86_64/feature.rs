#![allow(dead_code)]

use super::vcpu::GuestState;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

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

#[derive(Default, Copy, Clone, Debug)]
#[allow(non_camel_case_types)]
pub struct cpuid_leaf {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
}

#[repr(u32)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub enum x86_cpuid_leaf_num {
    X86_CPUID_BASE = 0,
    X86_CPUID_MODEL_FEATURES = 0x1,
    X86_CPUID_CACHE_V1 = 0x2,
    X86_CPUID_CACHE_V2 = 0x4,
    X86_CPUID_MON = 0x5,
    X86_CPUID_THERMAL_AND_POWER = 0x6,
    X86_CPUID_EXTENDED_FEATURE_FLAGS = 0x7,
    X86_CPUID_PERFORMANCE_MONITORING = 0xa,
    X86_CPUID_TOPOLOGY = 0xb,
    X86_CPUID_XSAVE = 0xd,
    X86_CPUID_PT = 0x14,
    X86_CPUID_TSC = 0x15,

    X86_CPUID_HYP_BASE = 0x40000000,
    // X86_CPUID_HYP_VENDOR = 0x40000000,
    X86_CPUID_KVM_FEATURES = 0x40000001,

    X86_CPUID_EXT_BASE = 0x80000000,
    X86_CPUID_BRAND = 0x80000002,
    X86_CPUID_ADDR_WIDTH = 0x80000008,
    X86_CPUID_AMD_TOPOLOGY = 0x8000001e,
}

#[derive(Clone, Copy, Debug)]
#[allow(non_camel_case_types)]
pub struct x86_cpuid_bit {
    pub leaf_num: u32,
    pub word: u8,
    pub bit: u8,
}

#[allow(non_snake_case)]
const fn X86_CPUID_BIT(leaf: u32, word: u8, bit: u8) -> x86_cpuid_bit {
    x86_cpuid_bit {
        leaf_num: leaf,
        word: word,
        bit: bit,
    }
}
#[allow(non_snake_case)]
fn BITS_SHIFT(x: u32, high: u32, low: u32) -> u32 {
    (x >> low) & ((1 << (high - low)) - 1)
}

/* cpu vendors */
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
enum x86_vendor_list {
    X86_VENDOR_UNKNOWN,
    X86_VENDOR_INTEL,
    X86_VENDOR_AMD,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct x86_model_info {
    processor_type: u8,
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
enum x86_microarch_list {
    X86_MICROARCH_UNKNOWN,
    X86_MICROARCH_INTEL_NEHALEM,
    X86_MICROARCH_INTEL_WESTMERE,
    X86_MICROARCH_INTEL_SANDY_BRIDGE,
    X86_MICROARCH_INTEL_IVY_BRIDGE,
    X86_MICROARCH_INTEL_BROADWELL,
    X86_MICROARCH_INTEL_HASWELL,
    X86_MICROARCH_INTEL_SKYLAKE,
    X86_MICROARCH_INTEL_KABYLAKE,
    X86_MICROARCH_INTEL_SILVERMONT, // Silvermont, Airmont
    X86_MICROARCH_INTEL_GOLDMONT,   // Goldmont, Goldmont+
    X86_MICROARCH_AMD_BULLDOZER,
    X86_MICROARCH_AMD_JAGUAR,
    X86_MICROARCH_AMD_ZEN,
}

lazy_static! {
    static ref S_CPUID: Mutex<Vec<cpuid_leaf>> = Mutex::new(Vec::new());
    static ref S_CPUID_HYP: Mutex<Vec<cpuid_leaf>> = Mutex::new(Vec::new());
    static ref S_CPUID_EXT: Mutex<Vec<cpuid_leaf>> = Mutex::new(Vec::new());
    static ref S_MAX_CPUID: Mutex<u32> = Mutex::new(0);
    static ref S_MAX_HYP_CPUID: Mutex<u32> = Mutex::new(0);
    static ref S_MAX_EXT_CPUID: Mutex<u32> = Mutex::new(0);
    static ref S_INITIALIZED: AtomicBool = AtomicBool::new(false);
    static ref S_X86_VENDOR: Mutex<x86_vendor_list> =
        Mutex::new(x86_vendor_list::X86_VENDOR_UNKNOWN);
    static ref S_MODEL_INFO: Mutex<x86_model_info> = Mutex::new(Default::default());
    static ref S_X86_MICROARCH: Mutex<x86_microarch_list> =
        Mutex::new(x86_microarch_list::X86_MICROARCH_UNKNOWN);
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union VendorInfo {
    pub vendor_id: [u32; 3],
    pub vendor_string: [u8; 12],
}
pub fn x86_feature_init() -> () {
    if S_INITIALIZED.swap(true, Ordering::Relaxed) {
        return;
    }

    S_CPUID
        .lock()
        .resize_with(MAX_SUPPORTED_CPUID as usize + 1, Default::default);
    S_CPUID_HYP.lock().resize_with(
        MAX_SUPPORTED_CPUID_HYP as usize - x86_cpuid_leaf_num::X86_CPUID_HYP_BASE as usize + 1,
        Default::default,
    );
    S_CPUID_EXT.lock().resize_with(
        MAX_SUPPORTED_CPUID_EXT as usize - x86_cpuid_leaf_num::X86_CPUID_EXT_BASE as usize + 1,
        Default::default,
    );

    /* test for cpuid count */
    let mut cpuid0: cpuid_leaf = Default::default();
    let res = raw_cpuid::cpuid!(0);
    cpuid0.a = res.eax;
    cpuid0.b = res.ebx;
    cpuid0.c = res.ecx;
    cpuid0.d = res.edx;
    S_CPUID.lock()[0] = cpuid0;

    let mut max_cpuid = cpuid0.a;
    if max_cpuid > MAX_SUPPORTED_CPUID {
        max_cpuid = MAX_SUPPORTED_CPUID;
    }
    *S_MAX_CPUID.lock() = max_cpuid;

    info!("[RVM] max cpuid {}", max_cpuid);

    /* figure out the vendor */
    let mut vu = VendorInfo { vendor_id: [0; 3] };
    unsafe { vu.vendor_id[0] = cpuid0.b };
    unsafe { vu.vendor_id[1] = cpuid0.d };
    unsafe { vu.vendor_id[2] = cpuid0.c };
    let vendor_string =
        core::str::from_utf8(unsafe { &vu.vendor_string }).expect("Error in getting vendor_string");
    if vendor_string == "GenuineIntel" {
        *S_X86_VENDOR.lock() = x86_vendor_list::X86_VENDOR_INTEL;
    } else if vendor_string == "AuthenticAMD" {
        *S_X86_VENDOR.lock() = x86_vendor_list::X86_VENDOR_AMD;
    } else {
        *S_X86_VENDOR.lock() = x86_vendor_list::X86_VENDOR_UNKNOWN;
    }
    info!("[RVM] X86 VENDOR is {:?}", *S_X86_VENDOR.lock());

    drop(cpuid0);

    /* read in the base cpuids */
    for i in 1..=max_cpuid {
        let mut data: cpuid_leaf = Default::default();
        let res = raw_cpuid::cpuid!(i, 0);
        data.a = res.eax;
        data.b = res.ebx;
        data.c = res.ecx;
        data.d = res.edx;
        S_CPUID.lock()[i as usize] = data;
    }

    /* test for extended cpuid count */
    let mut cpuid_base: cpuid_leaf = Default::default();
    let res = raw_cpuid::cpuid!(x86_cpuid_leaf_num::X86_CPUID_EXT_BASE);
    cpuid_base.a = res.eax;
    cpuid_base.b = res.ebx;
    cpuid_base.c = res.ecx;
    cpuid_base.d = res.edx;
    S_CPUID_EXT.lock()[0] = cpuid_base;

    let mut max_ext_cpuid = cpuid_base.a;
    if max_ext_cpuid > MAX_SUPPORTED_CPUID_EXT {
        max_ext_cpuid = MAX_SUPPORTED_CPUID_EXT;
    }
    *S_MAX_EXT_CPUID.lock() = max_ext_cpuid;

    info!("[RVM] max extended cpuid 0x{:x}", max_ext_cpuid);

    drop(cpuid_base);

    /* read in the extended cpuids */
    for i in (x86_cpuid_leaf_num::X86_CPUID_EXT_BASE as u32)..=max_ext_cpuid {
        let index = i - x86_cpuid_leaf_num::X86_CPUID_EXT_BASE as u32;
        let mut data: cpuid_leaf = Default::default();
        let res = raw_cpuid::cpuid!(i, 0);
        data.a = res.eax;
        data.b = res.ebx;
        data.c = res.ecx;
        data.d = res.edx;
        S_CPUID_EXT.lock()[index as usize] = data;
    }

    /* read in the hypervisor cpuids. the maximum leaf is reported at X86_CPUID_HYP_BASE. */
    let mut cpuid_hyp: cpuid_leaf = Default::default();
    let res = raw_cpuid::cpuid!(x86_cpuid_leaf_num::X86_CPUID_HYP_BASE);
    cpuid_hyp.a = res.eax;
    cpuid_hyp.b = res.ebx;
    cpuid_hyp.c = res.ecx;
    cpuid_hyp.d = res.edx;
    S_CPUID_HYP.lock()[0] = cpuid_hyp;

    let mut max_hyp_cpuid = cpuid_hyp.a;
    if max_hyp_cpuid > MAX_SUPPORTED_CPUID_HYP {
        max_hyp_cpuid = MAX_SUPPORTED_CPUID_HYP;
    }
    *S_MAX_HYP_CPUID.lock() = max_hyp_cpuid;

    info!("[RVM] max hypervisor cpuid 0x{:x}", max_hyp_cpuid);

    drop(cpuid_hyp);

    for i in (x86_cpuid_leaf_num::X86_CPUID_HYP_BASE as u32)..=max_hyp_cpuid {
        let index = i - (x86_cpuid_leaf_num::X86_CPUID_HYP_BASE as u32);
        let mut data: cpuid_leaf = Default::default();
        let res = raw_cpuid::cpuid!(i, 0);
        data.a = res.eax;
        data.b = res.ebx;
        data.c = res.ecx;
        data.d = res.edx;
        S_CPUID_HYP.lock()[index as usize] = data;
    }

    /* populate the model info */
    let leaf = x86_get_cpuid_leaf(x86_cpuid_leaf_num::X86_CPUID_MODEL_FEATURES);
    if let Some((mtx, idx)) = leaf {
        let leaf = mtx.lock()[idx];
        let mut model_info = x86_model_info {
            processor_type: BITS_SHIFT(leaf.a, 13, 12) as u8,
            family: BITS_SHIFT(leaf.a, 11, 8) as u8,
            model: BITS_SHIFT(leaf.a, 7, 4) as u8,
            stepping: BITS_SHIFT(leaf.a, 3, 0) as u8,
            display_family: BITS_SHIFT(leaf.a, 11, 8),
            display_model: BITS_SHIFT(leaf.a, 7, 4),

            patch_level: 0,
        };
        if model_info.family == 0xf {
            model_info.display_family += BITS_SHIFT(leaf.a, 27, 20);
        }
        if model_info.family == 0xf || model_info.family == 0x6 {
            model_info.display_model += BITS_SHIFT(leaf.a, 19, 16) << 4;
        }

        *S_MODEL_INFO.lock() = model_info;

        *S_X86_MICROARCH.lock() = get_microarch(&model_info);
    }

    // Get microcode patch level
    match *S_X86_VENDOR.lock() {
        x86_vendor_list::X86_VENDOR_INTEL => {
            S_MODEL_INFO.lock().patch_level = x86_intel_get_patch_level();
        }
        x86_vendor_list::X86_VENDOR_AMD => {
            S_MODEL_INFO.lock().patch_level = x86_amd_get_patch_level();
        }
        _ => {}
    }
    // x86_microarch_config = select_microarch_config(x86_microarch); // FIXME

    // FIXME some codes left

    info!("[RVM] success init features");
}

fn get_microarch(info: &x86_model_info) -> x86_microarch_list {
    let x86_vendor = *S_X86_VENDOR.lock();
    if x86_vendor == x86_vendor_list::X86_VENDOR_INTEL && info.family == 0x6 {
        match info.display_model {
            0x1a | 0x1e | 0x1f | 0x2e /* Nehalem */ =>
                x86_microarch_list::X86_MICROARCH_INTEL_NEHALEM,
            0x25 | 0x2c | 0x2f /* Westmere */ =>
                x86_microarch_list::X86_MICROARCH_INTEL_WESTMERE,
            0x2a| /* Sandy Bridge */
            0x2d /* Sandy Bridge EP */ =>
                x86_microarch_list::X86_MICROARCH_INTEL_SANDY_BRIDGE,
            0x3a| /* Ivy Bridge */
            0x3e /* Ivy Bridge EP */ =>
                x86_microarch_list::X86_MICROARCH_INTEL_IVY_BRIDGE,
            0x3c| /* Haswell DT */
            0x3f| /* Haswell MB */
            0x45| /* Haswell ULT */
            0x46 /* Haswell ULX */ =>
                x86_microarch_list::X86_MICROARCH_INTEL_HASWELL,
            0x3d| /* Broadwell */
            0x47| /* Broadwell H */
            0x56| /* Broadwell EP */
            0x4f /* Broadwell EX */ =>
                x86_microarch_list::X86_MICROARCH_INTEL_BROADWELL,
            0x4e| /* Skylake Y/U */
            0x5e| /* Skylake H/S */
            0x55 /* Skylake E */ =>
                x86_microarch_list::X86_MICROARCH_INTEL_SKYLAKE,
            0x8e| /* Kabylake Y/U */
            0x9e /* Kabylake H/S */ =>
                x86_microarch_list::X86_MICROARCH_INTEL_KABYLAKE,
            0x37| /* Silvermont */
            0x4a| /* Silvermont "Cherry View" */
            0x4d| /* Silvermont "Avoton" */
            0x4c| /* Airmont "Braswell" */
            0x5a /* Airmont */ =>
                x86_microarch_list::X86_MICROARCH_INTEL_SILVERMONT,
            0x5c /* Goldmont */ =>
                x86_microarch_list::X86_MICROARCH_INTEL_GOLDMONT,
            _ => x86_microarch_list::X86_MICROARCH_UNKNOWN
        }
    } else if x86_vendor == x86_vendor_list::X86_VENDOR_AMD && info.family == 0xf {
        match info.display_family { // zen
            0x15 /* Bulldozer */ =>
                x86_microarch_list::X86_MICROARCH_AMD_BULLDOZER,
            0x16 /* Jaguar */ =>
                x86_microarch_list::X86_MICROARCH_AMD_JAGUAR,
            0x17 /* Zen */ =>
                x86_microarch_list::X86_MICROARCH_AMD_ZEN,
            _ => x86_microarch_list::X86_MICROARCH_UNKNOWN
        }
    } else {
        x86_microarch_list::X86_MICROARCH_UNKNOWN
    }
}

fn x86_intel_get_patch_level() -> u32 {
    info!("[RVM] WARNING: running unimplemented fn x86_intel_get_patch_level");
    return 0;
}

fn x86_amd_get_patch_level() -> u32 {
    info!("[RVM] WARNING: running unimplemented fn x86_amd_get_patch_level");
    return 0;
}

fn x86_get_cpuid_leaf(
    leaf: x86_cpuid_leaf_num,
) -> Option<(&'static Mutex<Vec<cpuid_leaf>>, usize)> {
    let leaf = leaf as u32;

    if leaf < x86_cpuid_leaf_num::X86_CPUID_HYP_BASE as u32 {
        if leaf > *S_MAX_CPUID.lock() {
            return None;
        }
        return Some((&S_CPUID, leaf as usize));
    } else if leaf < x86_cpuid_leaf_num::X86_CPUID_EXT_BASE as u32 {
        if leaf > *S_MAX_HYP_CPUID.lock() {
            return None;
        }
        return Some((
            &S_CPUID_HYP,
            (leaf - x86_cpuid_leaf_num::X86_CPUID_HYP_BASE as u32) as usize,
        ));
    } else {
        if leaf > *S_MAX_EXT_CPUID.lock() {
            return None;
        }
        return Some((
            &S_CPUID_EXT,
            (leaf - x86_cpuid_leaf_num::X86_CPUID_EXT_BASE as u32) as usize,
        ));
    }
}

/* Retrieve the specified subleaf.  This function is not cached.
 * Returns false if leaf num is invalid */
pub fn x86_get_cpuid_subleaf(num: x86_cpuid_leaf_num, subleaf: u32, leaf: &mut cpuid_leaf) -> bool {
    let num = num as u32;
    if num < x86_cpuid_leaf_num::X86_CPUID_EXT_BASE as u32 {
        if num > *S_MAX_CPUID.lock() {
            return false;
        }
    } else if num > *S_MAX_EXT_CPUID.lock() {
        return false;
    }

    let res = raw_cpuid::cpuid!(num, subleaf);
    leaf.a = res.eax;
    leaf.b = res.ebx;
    leaf.c = res.ecx;
    leaf.d = res.edx;
    return true;
}

fn x86_feature_test(bit: x86_cpuid_bit) -> bool {
    assert!(bit.word <= 3 && bit.bit <= 31);

    if bit.word > 3 || bit.bit > 31 {
        return false;
    }

    let leaf = x86_get_cpuid_leaf(x86_cpuid_leaf_num::from(bit.leaf_num));
    match leaf {
        None => false,
        Some((mtx, idx)) => {
            let leaf = mtx.lock()[idx];
            match bit.word {
                0 => ((1u32 << bit.bit) & leaf.a) != 0,
                1 => ((1u32 << bit.bit) & leaf.b) != 0,
                2 => ((1u32 << bit.bit) & leaf.c) != 0,
                3 => ((1u32 << bit.bit) & leaf.d) != 0,
                _ => false,
            }
        }
    }
}

/* add feature bits to test here */
/* format: X86_CPUID_BIT(cpuid leaf, register (eax-edx:0-3), bit) */
pub const X86_FEATURE_SSE3: x86_cpuid_bit = X86_CPUID_BIT(0x1, 2, 0);
pub const X86_FEATURE_MON: x86_cpuid_bit = X86_CPUID_BIT(0x1, 2, 3);
pub const X86_FEATURE_VMX: x86_cpuid_bit = X86_CPUID_BIT(0x1, 2, 5);
pub const X86_FEATURE_TM2: x86_cpuid_bit = X86_CPUID_BIT(0x1, 2, 8);
pub const X86_FEATURE_SSSE3: x86_cpuid_bit = X86_CPUID_BIT(0x1, 2, 9);
pub const X86_FEATURE_PDCM: x86_cpuid_bit = X86_CPUID_BIT(0x1, 2, 15);
pub const X86_FEATURE_PCID: x86_cpuid_bit = X86_CPUID_BIT(0x1, 2, 17);
pub const X86_FEATURE_SSE4_1: x86_cpuid_bit = X86_CPUID_BIT(0x1, 2, 19);
pub const X86_FEATURE_SSE4_2: x86_cpuid_bit = X86_CPUID_BIT(0x1, 2, 20);
pub const X86_FEATURE_X2APIC: x86_cpuid_bit = X86_CPUID_BIT(0x1, 2, 21);
pub const X86_FEATURE_TSC_DEADLINE: x86_cpuid_bit = X86_CPUID_BIT(0x1, 2, 24);
pub const X86_FEATURE_AESNI: x86_cpuid_bit = X86_CPUID_BIT(0x1, 2, 25);
pub const X86_FEATURE_XSAVE: x86_cpuid_bit = X86_CPUID_BIT(0x1, 2, 26);
pub const X86_FEATURE_AVX: x86_cpuid_bit = X86_CPUID_BIT(0x1, 2, 28);
pub const X86_FEATURE_RDRAND: x86_cpuid_bit = X86_CPUID_BIT(0x1, 2, 30);
pub const X86_FEATURE_HYPERVISOR: x86_cpuid_bit = X86_CPUID_BIT(0x1, 2, 31);
pub const X86_FEATURE_FPU: x86_cpuid_bit = X86_CPUID_BIT(0x1, 3, 0);
pub const X86_FEATURE_SEP: x86_cpuid_bit = X86_CPUID_BIT(0x1, 3, 11);
pub const X86_FEATURE_CLFLUSH: x86_cpuid_bit = X86_CPUID_BIT(0x1, 3, 19);
pub const X86_FEATURE_ACPI: x86_cpuid_bit = X86_CPUID_BIT(0x1, 3, 22);
pub const X86_FEATURE_MMX: x86_cpuid_bit = X86_CPUID_BIT(0x1, 3, 23);
pub const X86_FEATURE_FXSR: x86_cpuid_bit = X86_CPUID_BIT(0x1, 3, 24);
pub const X86_FEATURE_SSE: x86_cpuid_bit = X86_CPUID_BIT(0x1, 3, 25);
pub const X86_FEATURE_SSE2: x86_cpuid_bit = X86_CPUID_BIT(0x1, 3, 26);
pub const X86_FEATURE_TM: x86_cpuid_bit = X86_CPUID_BIT(0x1, 3, 29);
pub const X86_FEATURE_DTS: x86_cpuid_bit = X86_CPUID_BIT(0x6, 0, 0);
pub const X86_FEATURE_PLN: x86_cpuid_bit = X86_CPUID_BIT(0x6, 0, 4);
pub const X86_FEATURE_PTM: x86_cpuid_bit = X86_CPUID_BIT(0x6, 0, 6);
pub const X86_FEATURE_HWP: x86_cpuid_bit = X86_CPUID_BIT(0x6, 0, 7);
pub const X86_FEATURE_HWP_NOT: x86_cpuid_bit = X86_CPUID_BIT(0x6, 0, 8);
pub const X86_FEATURE_HWP_ACT: x86_cpuid_bit = X86_CPUID_BIT(0x6, 0, 9);
pub const X86_FEATURE_HWP_PREF: x86_cpuid_bit = X86_CPUID_BIT(0x6, 0, 10);
pub const X86_FEATURE_HW_FEEDBACK: x86_cpuid_bit = X86_CPUID_BIT(0x6, 2, 0);
pub const X86_FEATURE_PERF_BIAS: x86_cpuid_bit = X86_CPUID_BIT(0x6, 2, 3);
pub const X86_FEATURE_FSGSBASE: x86_cpuid_bit = X86_CPUID_BIT(0x7, 1, 0);
pub const X86_FEATURE_TSC_ADJUST: x86_cpuid_bit = X86_CPUID_BIT(0x7, 1, 1);
pub const X86_FEATURE_AVX2: x86_cpuid_bit = X86_CPUID_BIT(0x7, 1, 5);
pub const X86_FEATURE_SMEP: x86_cpuid_bit = X86_CPUID_BIT(0x7, 1, 7);
pub const X86_FEATURE_ERMS: x86_cpuid_bit = X86_CPUID_BIT(0x7, 1, 9);
pub const X86_FEATURE_INVPCID: x86_cpuid_bit = X86_CPUID_BIT(0x7, 1, 10);
pub const X86_FEATURE_RDSEED: x86_cpuid_bit = X86_CPUID_BIT(0x7, 1, 18);
pub const X86_FEATURE_SMAP: x86_cpuid_bit = X86_CPUID_BIT(0x7, 1, 20);
pub const X86_FEATURE_CLFLUSHOPT: x86_cpuid_bit = X86_CPUID_BIT(0x7, 1, 23);
pub const X86_FEATURE_CLWB: x86_cpuid_bit = X86_CPUID_BIT(0x7, 1, 24);
pub const X86_FEATURE_PT: x86_cpuid_bit = X86_CPUID_BIT(0x7, 1, 25);
pub const X86_FEATURE_UMIP: x86_cpuid_bit = X86_CPUID_BIT(0x7, 2, 2);
pub const X86_FEATURE_PKU: x86_cpuid_bit = X86_CPUID_BIT(0x7, 2, 3);
pub const X86_FEATURE_MD_CLEAR: x86_cpuid_bit = X86_CPUID_BIT(0x7, 3, 10);
pub const X86_FEATURE_IBRS_IBPB: x86_cpuid_bit = X86_CPUID_BIT(0x7, 3, 26);
pub const X86_FEATURE_STIBP: x86_cpuid_bit = X86_CPUID_BIT(0x7, 3, 27);
pub const X86_FEATURE_L1D_FLUSH: x86_cpuid_bit = X86_CPUID_BIT(0x7, 3, 28);
pub const X86_FEATURE_ARCH_CAPABILITIES: x86_cpuid_bit = X86_CPUID_BIT(0x7, 3, 29);
pub const X86_FEATURE_SSBD: x86_cpuid_bit = X86_CPUID_BIT(0x7, 3, 31);

pub const X86_FEATURE_KVM_PVCLOCK_STABLE: x86_cpuid_bit = X86_CPUID_BIT(0x40000001, 0, 24);
pub const X86_FEATURE_AMD_TOPO: x86_cpuid_bit = X86_CPUID_BIT(0x80000001, 2, 22);
pub const X86_FEATURE_SYSCALL: x86_cpuid_bit = X86_CPUID_BIT(0x80000001, 3, 11);
pub const X86_FEATURE_NX: x86_cpuid_bit = X86_CPUID_BIT(0x80000001, 3, 20);
pub const X86_FEATURE_HUGE_PAGE: x86_cpuid_bit = X86_CPUID_BIT(0x80000001, 3, 26);
pub const X86_FEATURE_RDTSCP: x86_cpuid_bit = X86_CPUID_BIT(0x80000001, 3, 27);
pub const X86_FEATURE_INVAR_TSC: x86_cpuid_bit = X86_CPUID_BIT(0x80000007, 3, 8);

/// ========== some helper function

impl From<u32> for x86_cpuid_leaf_num {
    fn from(code: u32) -> Self {
        use x86_cpuid_leaf_num::*;
        match code {
            0 => X86_CPUID_BASE,
            0x1 => X86_CPUID_MODEL_FEATURES,
            0x2 => X86_CPUID_CACHE_V1,
            0x4 => X86_CPUID_CACHE_V2,
            0x5 => X86_CPUID_MON,
            0x6 => X86_CPUID_THERMAL_AND_POWER,
            0x7 => X86_CPUID_EXTENDED_FEATURE_FLAGS,
            0xa => X86_CPUID_PERFORMANCE_MONITORING,
            0xb => X86_CPUID_TOPOLOGY,
            0xd => X86_CPUID_XSAVE,
            0x14 => X86_CPUID_PT,
            0x15 => X86_CPUID_TSC,

            0x40000000 => X86_CPUID_HYP_BASE,
            // X86_CPUID_HYP_VENDOR = 0x40000000,
            0x40000001 => X86_CPUID_KVM_FEATURES,

            0x80000000 => X86_CPUID_EXT_BASE,
            0x80000002 => X86_CPUID_BRAND,
            0x80000008 => X86_CPUID_ADDR_WIDTH,
            0x8000001e => X86_CPUID_AMD_TOPOLOGY,
            c => {
                panic!("[RVM] unknow x86_cpuid_leaf_num: {}", c);
            }
        }
    }
}
