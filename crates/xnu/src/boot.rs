//! boot — XNU boot_args wire layout, boot args, startup phases, boot order.
//!
//! On real hardware iBoot hands the XNU kernel a `boot_args` structure in x0
//! at the kernel entry point (`start` in pexpert/arm/start.s); the emulator
//! must build the same structure for the guest kernel. This module encodes
//! the layout exactly as vendored in the reference repo, plus the kernel
//! boot-argument names, the STARTUP_SUB_* phase ladder and the ARM64 early
//! boot call order distilled from arm_init/machine_startup/kernel_bootstrap.
//!
//! Layout verification notes (checked against the reference headers):
//! * `pexpert/pexpert/arm64/boot.h` (the variant used here, matching the
//!   A13/ARM64 guest): `Boot_Video` is six `unsigned long` fields, i.e. six
//!   u64s on LP64 = 48 bytes (not 56); `boot_args` has u64 virtBase/physBase/
//!   memSize/topOfKernelData, a 608-byte CommandLine, and u64 bootFlags +
//!   memSizeActual at the tail. Neither header carries explicit pad fields;
//!   the 4-byte gaps after `Version` and `machine_type` (and before
//!   `boot_flags`) are implicit C/Rust natural alignment, which `repr(C)`
//!   reproduces. Computed `sizeof(boot_args)` = 736 = 0x2E0, asserted below.
//! * The sibling `pexpert/pexpert/arm/boot.h` is the 32-bit-era variant
//!   (u32 virtBase/physBase/memSize, BOOT_LINE_LENGTH = 256, u32 bootFlags +
//!   memSizeActual tail); its LP64 sizeof computes to 0x168. Neither header
//!   states a `sizeof` assert or the `vanguard` field of later xnu arm64
//!   revisions, so no 0x460/vanguard layout is encoded here.
//!
//! Source: darling-xnu (Darwin 20.6.0 lineage) pexpert/pexpert/arm64/boot.h
//! Source: darling-xnu pexpert/pexpert/arm/boot.h
//! Source: darling-xnu osfmk/kern/startup.h (STARTUP_SUB_* order)
//! Source: xnu osfmk/arm64 + kern/bootstrap ordering (distilled, as given by
//!         the arlinux-xnu project notes)

/// `BOOT_LINE_LENGTH` from pexpert/pexpert/arm64/boot.h (608, matching
/// iBoot's IBOOT_MAX_ENV_VAR_DATA_SIZE; the arm/ sibling uses 256).
pub const BOOT_LINE_LENGTH: usize = 608;

/// `kBootArgsRevision` — revision 1 of the boot_args structure.
pub const K_BOOT_ARGS_REVISION: u16 = 1;

/// `kBootArgsRevision2` — revision 2 added boot_args->bootFlags.
pub const K_BOOT_ARGS_REVISION_2: u16 = 2;

/// `kBootArgsVersion1`.
pub const K_BOOT_ARGS_VERSION_1: u16 = 1;

/// `kBootArgsVersion2`.
pub const K_BOOT_ARGS_VERSION_2: u16 = 2;

/// `kBootVideoDepthMask` — low 8 bits of `v_depth` are the pixel depth.
pub const K_BOOT_VIDEO_DEPTH_MASK: u64 = 0xFF;

/// `kBootVideoDepthDepthShift`.
pub const K_BOOT_VIDEO_DEPTH_DEPTH_SHIFT: u32 = 0;

/// `kBootVideoDepthRotateShift`.
pub const K_BOOT_VIDEO_DEPTH_ROTATE_SHIFT: u32 = 8;

/// `kBootVideoDepthScaleShift`.
pub const K_BOOT_VIDEO_DEPTH_SCALE_SHIFT: u32 = 16;

/// `kBootVideoDepthBootRotateShift`.
pub const K_BOOT_VIDEO_DEPTH_BOOT_ROTATE_SHIFT: u32 = 24;

/// `kBootFlagsDarkBoot` (arm64 header: 1ULL << 0).
pub const K_BOOT_FLAGS_DARK_BOOT: u64 = 1;

/// `struct Boot_Video` — six `unsigned long` fields on LP64 = 48 bytes.
///
/// Source: darling-xnu pexpert/pexpert/arm64/boot.h (struct Boot_Video)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BootVideo {
    /// Base address of video memory (v_baseAddr).
    pub v_base_addr: u64,
    /// Display code, if applicable (v_display).
    pub v_display: u64,
    /// Number of bytes per pixel row (v_rowBytes).
    pub v_row_bytes: u64,
    /// Width (v_width).
    pub v_width: u64,
    /// Height (v_height).
    pub v_height: u64,
    /// Pixel depth and other parameters (v_depth).
    pub v_depth: u64,
}

/// `boot_args` as vendored in pexpert/pexpert/arm64/boot.h — the structure
/// iBoot places in x0 at kernel entry. [`BOOT_ARGS_SIZE`] (736 = 0x2E0)
/// is the expected LP64 size; the 4-byte alignment gaps are implicit in the
/// C header and reproduced by `repr(C)`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BootArgs {
    /// Revision of boot_args structure (offset 0).
    pub revision: u16,
    /// Version of boot_args structure (offset 2; then 4 implicit pad bytes).
    pub version: u16,
    /// Virtual base of memory (offset 8).
    pub virt_base: u64,
    /// Physical base of memory (offset 16).
    pub phys_base: u64,
    /// Size of memory (offset 24).
    pub mem_size: u64,
    /// Highest physical address used in kernel data area (offset 32).
    pub top_of_kernel_data: u64,
    /// Video information (offset 40, 48 bytes).
    pub video: BootVideo,
    /// Machine type (offset 88; then 4 implicit pad bytes).
    pub machine_type: u32,
    /// Base of flattened device tree (offset 96).
    pub device_tree_p: u64,
    /// Length of flattened tree (offset 104).
    pub device_tree_length: u32,
    /// Passed-in command line (offset 108, [`BOOT_LINE_LENGTH`] bytes; the
    /// following u64 field forces 4 implicit pad bytes after it).
    pub command_line: [u8; BOOT_LINE_LENGTH],
    /// Additional flags specified by the bootloader (offset 720).
    pub boot_flags: u64,
    /// Actual size of memory (offset 728).
    pub mem_size_actual: u64,
}

/// Expected `sizeof(boot_args)` for the vendored arm64 layout:
/// 736 = 0x2E0. (Neither reference header contains a sizeof static assert;
/// this is the computed LP64 value, verified by the const assertion below.)
pub const BOOT_ARGS_SIZE: usize = 736;

const _: () = assert!(core::mem::size_of::<BootVideo>() == 48);
const _: () = assert!(core::mem::size_of::<BootArgs>() == BOOT_ARGS_SIZE);

/// Boot argument strings the ARM64 XNU kernel parses from
/// `boot_args->CommandLine`, grouped as parsed by the distillation: early
/// ARM platform tunables (serial, maxmem, wdt, debug, ...), dyld/shared-cache
/// knobs, debug flags, and the restore-lane args used by the restore stack
/// (rd=md0, -restore, kern.hv_vmm_present, kern.bootsessionuuid,
/// kern.bootargs).
///
/// Source: arlinux-xnu project distillation of xnu pexpert/arm64 + libkern
/// arg parsing (as supplied by the task brief).
pub const BOOT_ARGS_KNOWN: &[&str] = &[
    "serial",
    "maxmem",
    "wdt",
    "debug",
    "immediate_NMI",
    "cpus_defeatures",
    "vti",
    "bpret",
    "fastipi",
    "arm64_maxoffset",
    "alt-dyld",
    "drain_uart_sync",
    "interrupt_masked_debug_timeout",
    "-v",
    "-x",
    "-s",
    "-zp",
    "-no-zp",
    "-minimalboot",
    "-disable_aslr",
    "-show_pointers",
    "-novfscache",
    "-zleakon",
    "-zleakoff",
    "-panic_on_exception_triage",
    "-unsafe_kernel_text",
    "-no_slto_panic",
    "bootprofile_interval",
    "trace_typefilter",
    // restore lane
    "rd=md0",
    "-restore",
    "kern.hv_vmm_present",
    "kern.bootsessionuuid",
    "kern.bootargs",
];

/// `STARTUP_SUB_*` ladder from osfmk/kern/startup.h, in registration order
/// (STARTUP_SUB_NONE = 0 .. STARTUP_SUB_LOCKDOWN = ~0u). Each entry names the
/// subsystem whose STARTUP() hooks run at that phase.
///
/// Source: darling-xnu osfmk/kern/startup.h (enum startup_subsystem)
pub const STARTUP_PHASES: &[&str] = &[
    "NONE",
    "TUNABLES",
    "LOCKS_EARLY",
    "KPRINTF",
    "PMAP_STEAL",
    "VM_KERNEL",
    "KMEM",
    "KMEM_ALLOC",
    "ZALLOC",
    "PERCPU",
    "LOCKS",
    "CODESIGNING",
    "OSLOG",
    "MACH_IPC",
    "SYSCTL",
    "EARLY_BOOT",
    "LOCKDOWN",
];

/// ARM64 early boot call order distilled from arm_init / machine_startup /
/// kernel_bootstrap, one call per entry, in execution order from the start.s
/// entry to userspace bootstrap (launchd).
///
/// Source: xnu osfmk/arm64 (arm_init, machine_startup, machine_init,
/// kernel_bootstrap, kernel_bootstrap_thread) + osfmk/kern (sched_init,
/// waitq_bootstrap, task_init, thread_init, exception_init), distilled by the
/// arlinux-xnu project (as supplied by the task brief).
pub const ARM64_BOOT_CALL_ORDER: &[&str] = &[
    "start.s entry (boot args in x0)",
    "arm_init(args)",
    "arm_slide_rebase_and_sign_image()",
    "copy args to const_boot_args",
    "cpu_data_init(&BootCpuData)",
    "PE_init_platform(FALSE, args)",
    "page size select (memSize>1GiB => 16KiB)",
    "ml_parse_cpu_topology()",
    "thread_bootstrap()",
    "cpu_bootstrap()",
    "rtclock_early_init()",
    "kernel_startup_bootstrap()",
    "timer_call_init()",
    "cpu_init()",
    "processor_bootstrap()",
    "read maxmem/hw.memsize",
    "arm_vm_init(xmaxmem, args)",
    "PE_init_platform(TRUE, &BootCpuData)",
    "cpu_timebase_init()",
    "PE_init_cpu()",
    "fiq_context_init()",
    "DT /chosen dram-base/dram-size",
    "__stack_chk_guard = early_random()",
    "machine_startup(args)",
    "machine_conf()",
    "kernel_bootstrap()",
    "console_init()",
    "sched_init()",
    "waitq_bootstrap()",
    "mac_policy_init()",
    "PMAP_ACTIVATE_KERNEL",
    "machine_init()",
    "clock_init()",
    "task_init()/thread_init()",
    "exception_init()",
    "kernel_bootstrap_thread()",
    "sched_startup()",
    "thread_call_initialize()",
    "clock_service_create()",
    "device_service_create()",
    "kdp_init()",
    "hv_support_init()",
    "PE_init_iokit()",
    "vm_commpage_init()",
    "mac_policy_initmach()",
    "trust_cache_init()",
    "machine_lockdown()",
    "userspace bootstrap (launchd)",
];
