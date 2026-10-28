fn main() {
    let dir = std::env::var("IOS_RUST_FIXTURES").unwrap();
    let data = std::fs::read(format!("{dir}/kernelcache.release.iphone12b")).unwrap();
    let img = kernelcache::decompress(&data).unwrap();
    let info = kernelcache::sections::section_bytes(&img, "__PRELINK_INFO", "__info").unwrap();
    std::fs::write("/tmp/__info.plist", info).unwrap();
    println!("wrote {} bytes", info.len());
}
