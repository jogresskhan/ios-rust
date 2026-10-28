//! CLI flag parser — the drop-in subset of qemu-system-aarch64 flags the
//! restore lane actually passes (see lanes/t8030-inferno lab16 launcher).
//!
//! Supported today:
//!   -M apple-t8030 | t8030        machine
//!   -cpu apple-a13                cpu model (informational; fixed per machine)
//!   -kernel <file>                kernelcache (mach-o fileset)
//!   -dtb <file>                   device tree (ADT)
//!   -append <args>                cmdline
//!   -serial mon:stdio | file:path console sink
//!   -drive file=...,format=raw    backing storage (ANS/NVMe)
//!   -nographic                    headless
//!   -enable-kvm etc.              accepted-and-ignored for script compat

use std::path::PathBuf;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct QemuCli {
    pub machine: Option<String>,
    pub cpu: Option<String>,
    pub kernel: Option<PathBuf>,
    pub dtb: Option<PathBuf>,
    pub append: Option<String>,
    pub drives: Vec<PathBuf>,
    pub serial_file: Option<PathBuf>,
    pub nographic: bool,
    pub ignored: Vec<String>,
}

impl QemuCli {
    /// Parse the argv subset. Unknown `-flag value` pairs land in `ignored`
    /// (so existing lane scripts keep running while parity grows).
    pub fn parse<S: AsRef<str>>(args: &[S]) -> Result<Self, String> {
        let mut cli = QemuCli::default();
        let mut it = args.iter().map(|s| s.as_ref());
        while let Some(flag) = it.next() {
            match flag {
                "-M" | "-machine" => cli.machine = it.next().map(String::from),
                "-cpu" => cli.cpu = it.next().map(String::from),
                "-kernel" => cli.kernel = it.next().map(PathBuf::from),
                "-dtb" => cli.dtb = it.next().map(PathBuf::from),
                "-append" => cli.append = it.next().map(String::from),
                "-serial" => {
                    let v = it.next().ok_or("-serial needs value")?;
                    if let Some(path) = v.strip_prefix("file:") {
                        cli.serial_file = Some(PathBuf::from(path));
                    }
                }
                "-drive" => {
                    let v = it.next().ok_or("-drive needs value")?;
                    let file = v
                        .split(',')
                        .find_map(|kv| kv.strip_prefix("file="))
                        .ok_or("-drive needs file=")?;
                    cli.drives.push(PathBuf::from(file));
                }
                "-nographic" => cli.nographic = true,
                other if other.starts_with('-') => {
                    // flags with a following value we knowingly ignore
                    if matches!(
                        other,
                        "-enable-kvm"
                            | "-no-reboot"
                            | "-no-shutdown"
                            | "-nodefaults"
                            | "-S"
                            | "-nographic"
                    ) {
                        cli.ignored.push(other.into());
                    } else if let Some(v) = it.next() {
                        cli.ignored.push(format!("{other} {v}"));
                    } else {
                        cli.ignored.push(other.into());
                    }
                }
                other => cli.ignored.push(other.into()),
            }
        }
        Ok(cli)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lane_flags() {
        let cli = QemuCli::parse(&[
            "-M",
            "apple-t8030",
            "-kernel",
            "kernelcache.im4p",
            "-dtb",
            "adt.img4",
            "-append",
            "debug=0x14",
            "-serial",
            "file:console.log",
            "-drive",
            "file=rootfs.dmg,format=raw",
            "-enable-kvm",
        ])
        .unwrap();
        assert_eq!(cli.machine.as_deref(), Some("apple-t8030"));
        assert_eq!(cli.kernel.as_deref(), Some(std::path::Path::new("kernelcache.im4p")));
        assert_eq!(cli.serial_file, Some(PathBuf::from("console.log")));
        assert_eq!(cli.drives, vec![PathBuf::from("rootfs.dmg")]);
        assert!(cli.ignored.iter().any(|s| s.contains("enable-kvm")));
    }
}
