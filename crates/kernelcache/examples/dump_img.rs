fn main() {
    let args: Vec<String> = std::env::args().collect();
    let data = std::fs::read(&args[1]).unwrap();
    let img = kernelcache::decompress(&data).unwrap();
    std::fs::write(&args[2], &img).unwrap();
    println!("wrote decompressed: {} bytes", img.len());
}
