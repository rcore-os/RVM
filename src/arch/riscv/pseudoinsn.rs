use bit_field::BitField;
#[inline]
pub fn get_addr_offset(insn: usize) -> usize {
    return insn.get_bits(15..20);
}
#[inline]
pub fn get_op_size_and_extension(insn: usize) -> (usize, bool) {
    match insn.get_bits(12..15) {
        0b000 => (1, false),
        0b001 => (2, false),
        0b010 => (4, false),
        0b011 => (8, false),
        0b100 => (1, true),
        0b101 => (2, true),
        0b110 => (4, true),
        _ => panic!("bad pseudo-op."),
    }
}
#[inline]
pub fn get_dst_register(insn: usize) -> usize {
    return insn.get_bits(7..12);
}

#[inline]
pub fn get_src_register(insn: usize) -> usize {
    return insn.get_bits(20..24);
}
