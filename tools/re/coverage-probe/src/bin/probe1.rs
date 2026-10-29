use a13_cpu::decode::decode;
fn main() {
    for w in [0x0F820020u32] {
        println!("{w:08X} -> {}", decode(0, w).map(|i| format!("{i:?}")).unwrap_or("None".into()));
    }
}
