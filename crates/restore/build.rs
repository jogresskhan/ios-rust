//! Builds the vendored Apple LZFSE C decoder (BSD-3, see vendor/PROVENANCE.md).

fn main() {
    let dir = std::path::Path::new("vendor");
    let sources = [
        "vendor/lzfse_decode.c",
        "vendor/lzfse_decode_base.c",
        "vendor/lzfse_fse.c",
        "vendor/lzvn_decode_base.c",
    ];
    for s in &sources {
        println!("cargo:rerun-if-changed={s}");
    }
    let mut build = cc::Build::new();
    for s in sources {
        let p = dir.join(s.trim_start_matches("vendor/"));
        if p.exists() {
            build.file(p);
        }
    }
    build
        .include(dir)
        .flag_if_supported("-O2")
        .compile("lzfse_dec");
}
