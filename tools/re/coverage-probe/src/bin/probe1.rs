use a13_cpu::decode::decode;
fn main() {
    for (n, w) in [("fjcvtzs", 0x1E7E0020u32), ("sqrdmlah", 0x6F42C020), ("mk-sqrdmlah", 0x6F42C020)] {
        println!("{n:12} {w:08X} -> {}", decode(0, w).map(|i| format!("{i:?}")).unwrap_or("None".into()));
    }
    // reconstruct mk word: q=1,u=1,size=2,opcode=0b1100,l=1,m=0,h=0,?
    // try bits: 0Q001111 size L M 1100 H 0 Rn Rd with rn=2,rd=2
    let w = 0x6F40_0000u32 | (2 << 22) | (0b1100 << 12) | (1 << 21) | (2 << 5) | 2;
    println!("mk-recon    {w:08X} -> {}", decode(0, w).map(|i| format!("{i:?}")).unwrap_or("None".into()));
}
