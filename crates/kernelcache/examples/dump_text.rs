fn main() {
    let dir = std::env::var("IOS_RUST_FIXTURES").unwrap_or("fixtures".into());
    let data = std::fs::read(format!("{dir}/kernelcache.release.iphone12b")).unwrap();
    let img = kernelcache::decompress(&data).unwrap();
    let text = kernelcache::sections::find_section(&img, "__TEXT_EXEC", "__text").unwrap();
    let anchor = kernelcache::sections::find_section(&img, "__TEXT", "__cstring").unwrap();
    let base = anchor.addr - anchor.offset;
    println!("text VA {:#x} offset {:#x} image_base {:#x}", text.addr, text.offset, base);
    let start = text.offset as usize;
    for i in 0..12 {
        let off = start + i * 4;
        let w = u32::from_le_bytes(img[off..off+4].try_into().unwrap());
        println!("  +{:<3} {:#010x}  {:#034x}", i * 4, w, text.addr + (i*4) as u64);
    }
}
