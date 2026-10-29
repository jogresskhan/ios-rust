//! unkdump: write every word in __TEXT_EXEC.__text that our decoder rejects
//! to (index:u32, word:u32) LE pairs, for the python capstone census.

use a13_cpu::decode::decode;
use kernelcache::sections::find_section;
use std::io::Write;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: unkdump <kernelcache> <out.bin>");
        std::process::exit(1);
    }
    let raw = std::fs::read(&args[1]).unwrap();
    let img = kernelcache::decompress(&raw).unwrap();
    let text = find_section(&img, "__TEXT_EXEC", "__text").expect("no __TEXT_EXEC.__text");
    let code = &img[text.offset as usize..(text.offset + text.size) as usize];
    let n = code.len() / 4;

    let mut out = Vec::with_capacity(n * 8 / 10);
    let mut unk = 0u64;
    for i in 0..n {
        let w = u32::from_le_bytes(code[i * 4..i * 4 + 4].try_into().unwrap());
        if decode(text.addr + (i as u64) * 4, w).is_none() {
            unk += 1;
            out.extend_from_slice(&(i as u32).to_le_bytes());
            out.extend_from_slice(&w.to_le_bytes());
        }
    }
    let mut f = std::fs::File::create(&args[2]).unwrap();
    f.write_all(&out).unwrap();
    eprintln!("unknown {unk}/{n} words -> {}", args[2]);
}
