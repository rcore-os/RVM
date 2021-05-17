#[repr(C)]
#[derive(Debug, Default)]
pub struct VcpuState {
    pub x: [u64; 31],
    pub sp: u64,
    pub cpsr: u64,
    pub _padding1: [u8; 4],
}
