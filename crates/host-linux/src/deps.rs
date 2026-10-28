//! deps — distro dependency manifest and build recipes, distilled from the
//! ios-emulator-linux install scripts.
//!
//! Parity: see PARITY.md row `host-linux`.
//! Source: ios-emulator-linux scripts/00-install-deps.sh (apt lists, ipsw/ldid notes),
//!         scripts/10-build-qemu.sh (QEMU configure/make), linux-apfs-rw README (module)

/// Base apt packages for building QEMU + the restore tooling on Debian/Ubuntu.
pub const APT_PACKAGES: &[&str] = &[
    "build-essential",
    "git",
    "python3",
    "python3-pip",
    "python3-venv",
    "libpixman-1-dev",
    "libglib2.0-dev",
    "libfdt-dev",
    "libslirp-dev",
    "ninja-build",
    "meson",
    "pkg-config",
    "zlib1g-dev",
    "libcapstone-dev",
    "libncurses-dev",
    "libusb-1.0-0-dev",
    "libgnutls28-dev",
    "libtasn1-dev",
    "cmake",
    "jq",
    "curl",
    "wget",
    "unzip",
    "libssl-dev",
    "flex",
    "bison",
];

/// Extra packages the upstream scripts install only under WSL2 (kernel build
/// helpers for the APFS/usbipd path and misc compression tools).
pub const APT_PACKAGES_WSL: &[&str] = &[
    "bc",
    "libelf-dev",
    "dwarves",
    "rsync",
    "cpio",
    "kmod",
    "libplist-dev",
    "uuid-dev",
    "libfuse3-dev",
    "libbz2-dev",
    "libattr1-dev",
];

/// Render one `sudo apt install -y ...` line: base packages plus `extra`
/// (callers typically pass [`APT_PACKAGES_WSL`] under WSL2, and any task-specific
/// packages on top).
pub fn apt_install_cmd(extra: &[&str]) -> String {
    let mut all = APT_PACKAGES.to_vec();
    all.extend_from_slice(extra);
    format!("sudo apt install -y {}", all.join(" "))
}

/// Canonical blacktop/ipsw install from GitHub release assets.
///
/// WARNING: the `pip install ipsw` fallback seen in some upstream scripts
/// installs a DIFFERENT, UNRELATED PyPI package — it does not provide
/// blacktop/ipsw and will quietly break every later step.
pub const IPSW_INSTALL_RECIPE: &str = r#"# blacktop/ipsw — canonical Linux install from GitHub release assets:
#   VER=$(curl -s https://api.github.com/repos/blacktop/ipsw/releases/latest | jq -r .tag_name | sed 's/^v//')
#   curl -fL -o /tmp/ipsw.tar.gz "https://github.com/blacktop/ipsw/releases/download/v${VER}/ipsw_${VER}_linux_x86_64.tar.gz"
#   sudo tar -xzf /tmp/ipsw.tar.gz -C /usr/local/bin ipsw
#   sudo chmod +x /usr/local/bin/ipsw && ipsw version
# On aarch64 hosts use ipsw_${VER}_linux_arm64.tar.gz instead of _x86_64.
# NOTE: the pip `ipsw` fallback in the upstream scripts is the WRONG tool —
# the PyPI package of that name is unrelated to blacktop/ipsw."#;

/// ProcursusTeam/ldid build + the ad-hoc signing gotcha.
pub const LDID_INSTALL_RECIPE: &str = r#"# ldid (ProcursusTeam) — ad-hoc Mach-O/code signing for the boot chain:
#   git clone https://github.com/ProcursusTeam/ldid.git
#   cd ldid && make -j"$(nproc)"
#   sudo make install PREFIX=/usr/local    # installs /usr/local/bin/ldid
# SIGNING GOTCHA: sign kernelcaches / TrustCache inputs with `ldid -Cadhoc`.
# -Cadhoc sets CodeDirectory flags to 0x2 (CS_ADHOC), which is what TXM/AMFI
# require on SPTM-era chips (A15/M2 and later); a plain `ldid -S` (flags 0x0)
# is rejected on those platforms. On the A13/T8030 boot path plain -S happens
# to be tolerated, but -Cadhoc is the safe default everywhere."#;

/// linux-apfs-rw module build, needed to mount ramdisk.dmg images on the host.
pub const APFS_MODULE_RECIPE: &str = r#"# linux-apfs-rw — APFS filesystem module for Linux (mount ramdisk.dmg):
#   git clone https://github.com/linux-apfs/linux-apfs-rw.git
#   cd linux-apfs-rw
#   ./genver.sh                        # regenerates version.h from git describe
#   make APFS_CONFIG=-DCONFIG_APFS_RW_ALWAYS -j"$(nproc)"
#   sudo insmod apfs.ko
# Verify the module registered: grep -w apfs /proc/filesystems
# (host_linux::check::check() reports this as apfs_module)"#;

/// QEMU build for the darwin machine (aarch64-softmmu only, no GUI backends).
pub const QEMU_BUILD_RECIPE: &str = r#"# QEMU (darwin-vm fork) — configure/build for aarch64-softmmu:
#   git clone --recursive <darwin-vm qemu fork> qemu-darwin
#   cd qemu-darwin && mkdir build && cd build
#   ../configure --target-list=aarch64-softmmu --disable-pvg --disable-werror \
#                --disable-docs --disable-gtk --disable-sdl
#   make -j"$(nproc)" || make -j2 || make -j1   # OOM fallback chain
#   sudo make install
# The OOM fallback chain matters: linking TCG on 8 GB hosts dies with -j"$(nproc)"."#;
