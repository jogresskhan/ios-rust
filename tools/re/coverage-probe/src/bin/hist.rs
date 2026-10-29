use a13_cpu::decode::decode;

fn main() {
    let kc = std::env::args().nth(1).expect("usage: hist <kernelcache>");
    let raw = std::fs::read(&kc).unwrap();
    let img = kernelcache::decompress(&raw).unwrap();
    let text = kernelcache::sections::find_section(&img, "__TEXT_EXEC", "__text").unwrap();
    let anchor = kernelcache::sections::find_section(&img, "__TEXT", "__cstring").unwrap();
    let base = anchor.addr - anchor.offset;
    let va0 = base + text.offset;
    let code = &img[text.offset as usize..(text.offset + text.size) as usize];
    let n = code.len() / 4;
    let mut buckets: std::collections::BTreeMap<u32, (u64, Vec<u32>)> = Default::default();
    for i in 0..n {
        let w = u32::from_le_bytes(code[i * 4..i * 4 + 4].try_into().unwrap());
        if decode(va0 + (i as u64) * 4, w).is_none() {
            let k = w >> 24;
            let e = buckets.entry(k).or_insert((0, Vec::new()));
            e.0 += 1;
            if e.1.len() < 3 { e.1.push(w); }
        }
    }
    let mut v: Vec<_> = buckets.into_iter().collect();
    v.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    let total: u64 = v.iter().map(|(_, (c, _))| c).sum();
    println!("total unknown: {total}");
    for (k, (c, ex)) in v.iter().take(14) {
        let exs: Vec<String> = ex.iter().map(|w| format!("{w:#010x}")).collect();
        println!("  top8={k:#04x} count={c} ({:.1}%) e.g. {}", (*c) as f64 * 100.0 / total as f64, exs.join(" "));
    }
}
