use a13_cpu::decode::decode;
fn main() {
    for a in std::env::args().skip(1) {
        let w = u32::from_str_radix(a.trim_start_matches("0x"), 16).unwrap();
        match decode(0, w) {
            Some(i) => println!("0x{w:08x} -> {:?}", std::mem::discriminant(&i)),
            None => println!("0x{w:08x} -> None"),
        }
    }
}
