//! abi — ARM64 Darwin ABI constants distilled from darwin-abi.h.
//!
//! Every constant here is a guest-visible wire value (never a host Linux
//! definition). The layout mirrors the distilled header: SVC/entry encoding,
//! platform syscalls, VM/mmap flags, open/mount/fcntl/rlimit knobs, port
//! rights and types, Mach message options and error codes, MIG subroutine
//! IDs, ulock and workqueue flags, kevent filters/flags/notes, commpage
//! offsets and the documented wire sizes of the remaining small structs.
//!
//! Not transcribed (absent from the distilled header): the classic Mach
//! port-name scheme constants (task = 0x103, host = 0x203, clock = 0x10003,
//! thread base = 0x200) and any iOS-16-era source pins beyond the
//! "xnu-8796.141.3 mach/message.h" citation already noted on the mach_msg2
//! hints in `mach_traps`. Port name assignment is kernel-internal and the
//! header only documents `darwin_port_generation` (see below).
//!
//! Source: arlinux-xnu src/darwin-abi.h (all enums/defines in this file)
//! Source: xnu bsd/sys/{errno,fcntl,mman,stat,ulock}.h,
//!         osfmk/kern/syscall_sw.c, mach/{kern_return,message}.h,
//!         mach/{mach_host,task}.defs, arm/cpu_capabilities.h,
//!         libpthread-330.250.2 kern/kern_internal.h (upstream identity)

// ---------------------------------------------------------------------------
// SVC entry encoding (ARM64)
// ---------------------------------------------------------------------------

/// Encoding of the `svc #0` instruction guests use to trap into the kernel.
pub const D_ARM64_INSN_SVC_0: u32 = 0xd400_0001;

/// Encoding of the canary-loading `movz x8, #imm` sequence probe
/// (`D_ARM64_INSN_MOVZ_X8`).
pub const D_ARM64_INSN_MOVZ_X8: u32 = 0xd280_0008;

/// Shift of the 16-bit immediate inside a MOVZ instruction.
pub const D_ARM64_MOVZ_IMMEDIATE_SHIFT: u32 = 5;

/// Register that carries the syscall/Mach-trap selector across `svc #0`
/// (`D_ARM64_SYSCALL_REGISTER`).
pub const D_ARM64_SYSCALL_REGISTER: u32 = 16;

/// CPSR carry bit (`D_ARM64_CARRY` = 1 << 29 = 0x20000000): BSD syscalls set
/// it to signal that x0 holds a positive Darwin errno.
pub const D_ARM64_CARRY: u64 = 1 << 29;

// ---------------------------------------------------------------------------
// Platform syscalls (x16 = 0x80000000, operation in x0)
// ---------------------------------------------------------------------------

/// x16 value selecting the platform syscall table.
pub const PLATFORM_SYSCALL_TRAP_NO: u32 = 0x8000_0000;

/// Platform operation: set thread-specific data pointer.
pub const PLATFORM_SET_TSD: u32 = 2;

/// Platform operation: get thread-specific data pointer.
pub const PLATFORM_GET_TSD: u32 = 3;

// ---------------------------------------------------------------------------
// VM flags (mach_vm_allocate/mach_vm_map, mmap)
// ---------------------------------------------------------------------------

/// mach_vm_allocate: any address is acceptable.
pub const VM_FLAGS_ANYWHERE: u32 = 1;

/// mach_vm_allocate: purgable allocation.
pub const VM_FLAGS_PURGABLE: u32 = 2;

/// mach_vm_*: user tag lives in this mask of the flags word.
pub const VM_FLAGS_TAG_MASK: u32 = 0xff00_0000;

/// mmap: sharing is shared.
pub const MAP_SHARED: u32 = 1;

/// mmap: sharing is private (copy-on-write).
pub const MAP_PRIVATE: u32 = 2;

/// mmap: interpret addr exactly.
pub const MAP_FIXED: u32 = 0x10;

/// mmap: anonymous memory.
pub const MAP_ANON: u32 = 0x1000;

/// mmap: resilient media mapping.
pub const MAP_RESILIENT_MEDIA: u32 = 0x4000;

/// mmap: POSIX 2001 semantics.
pub const MAP_UNIX03: u32 = 0x4_0000;

// ---------------------------------------------------------------------------
// open/openat/at flags, guards, protection classes
// ---------------------------------------------------------------------------

/// openat: pseudo dirfd meaning current working directory.
pub const AT_FDCWD: i32 = -2;

/// openat/fstatat: do not follow symlinks.
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x20;

/// unlinkat: remove a directory.
pub const AT_REMOVEDIR: u32 = 0x80;

/// open: write-only.
pub const O_WRONLY: u32 = 1;

/// open: read-write.
pub const O_RDWR: u32 = 2;

/// open: non-blocking.
pub const O_NONBLOCK: u32 = 0x4;

/// open: append.
pub const O_APPEND: u32 = 8;

/// open: do not follow final symlink.
pub const O_NOFOLLOW: u32 = 0x100;

/// open: create if missing.
pub const O_CREAT: u32 = 0x200;

/// open: truncate.
pub const O_TRUNC: u32 = 0x400;

/// open: exclusive create.
pub const O_EXCL: u32 = 0x800;

/// open: must be a directory.
pub const O_DIRECTORY: u32 = 0x10_0000;

/// open: close on exec.
pub const O_CLOEXEC: u32 = 0x100_0000;

/// open: close on fork.
pub const O_CLOFORK: u32 = 0x0800_0000;

/// open: fail if final component is a symlink flagged by a guard.
pub const O_NOFOLLOW_ANY: u32 = 0x2000_0000;

/// Guarded file descriptor known-guard mask (guarded_open_np family).
pub const GUARD_KNOWN_MASK: u32 = 0x1f;

/// Content protection class: default.
pub const PROTECTION_CLASS_DEFAULT: i32 = -1;

/// Content protection class: directory none.
pub const PROTECTION_CLASS_DIR_NONE: u32 = 0;

/// Content protection class F (complete until first user authentication).
pub const PROTECTION_CLASS_F: u32 = 6;

// ---------------------------------------------------------------------------
// Mount flags (getfsstat64/statfs64)
// ---------------------------------------------------------------------------

/// Read-only filesystem.
pub const MNT_RDONLY: u32 = 1;

/// Synchronous filesystem.
pub const MNT_SYNCHRONOUS: u32 = 2;

/// No exec from this filesystem.
pub const MNT_NOEXEC: u32 = 4;

/// No setuid/setgid.
pub const MNT_NOSUID: u32 = 8;

/// No device files.
pub const MNT_NODEV: u32 = 16;

/// No access-time updates.
pub const MNT_NOATIME: u32 = 0x1000_0000;

// ---------------------------------------------------------------------------
// Local (AF_UNIX) socket arguments for socketpair
// ---------------------------------------------------------------------------

/// AF_LOCAL (= AF_UNIX).
pub const AF_LOCAL: u32 = 1;

/// SOCK_STREAM.
pub const SOCK_STREAM: u32 = 1;

/// SOCK_DGRAM.
pub const SOCK_DGRAM: u32 = 2;

/// SOCK_SEQPACKET.
pub const SOCK_SEQPACKET: u32 = 5;

// ---------------------------------------------------------------------------
// Legacy hardware sysctl MIB (sysctl uses an int page size)
// ---------------------------------------------------------------------------

/// sysctl MIB top level: hardware.
pub const CTL_HW: u32 = 6;

/// sysctl MIB hw.pagesize.
pub const HW_PAGESIZE: u32 = 7;

// ---------------------------------------------------------------------------
// Device (makedev) layout
// ---------------------------------------------------------------------------

/// dev_t major number shift.
pub const DEV_MAJOR_SHIFT: u32 = 24;

/// dev_t major number maximum.
pub const DEV_MAJOR_MAX: u32 = 255;

/// dev_t minor number maximum.
pub const DEV_MINOR_MAX: u32 = 0x00ff_ffff;

// ---------------------------------------------------------------------------
// Port rights, types, options, generation
// ---------------------------------------------------------------------------

/// Right: send.
pub const PORT_RIGHT_SEND: u32 = 0;

/// Right: receive.
pub const PORT_RIGHT_RECEIVE: u32 = 1;

/// Right: port set.
pub const PORT_RIGHT_PORT_SET: u32 = 3;

/// Right: dead name.
pub const PORT_RIGHT_DEAD_NAME: u32 = 4;

/// Maximum user reference count per send right.
pub const PORT_UREFS_MAX: u32 = 65535;

/// MACH_PORT_TYPE_SEND bit pattern returned by mach_port_type.
pub const PORT_TYPE_SEND: u32 = 0x1_0000;

/// MACH_PORT_TYPE_RECEIVE.
pub const PORT_TYPE_RECEIVE: u32 = 0x2_0000;

/// MACH_PORT_TYPE_PORT_SET.
pub const PORT_TYPE_PORT_SET: u32 = 0x8_0000;

/// MACH_PORT_TYPE_DEAD_NAME.
pub const PORT_TYPE_DEAD_NAME: u32 = 0x10_0000;

/// mach_port_construct option: use context as guard.
pub const MPO_CONTEXT_AS_GUARD: u32 = 1;

/// mach_port_construct option: set queue limit.
pub const MPO_QLIMIT: u32 = 2;

/// mach_port_construct option: temporary owner.
pub const MPO_TEMPOWNER: u32 = 4;

/// mach_port_construct option: importance receiver.
pub const MPO_IMPORTANCE_RECEIVER: u32 = 8;

/// mach_port_construct option: insert a send right.
pub const MPO_INSERT_SEND_RIGHT: u32 = 0x10;

/// mach_port_construct option: strict.
pub const MPO_STRICT: u32 = 0x20;

/// Default port queue limit.
pub const PORT_QLIMIT_DEFAULT: u32 = 5;

/// Maximum port queue limit.
pub const PORT_QLIMIT_MAX: u32 = 1024;

/// ipc_entry generation step: low two bits stay set so dispatch (port
/// right name tagging) can rely on them (ipc_entry.h).
pub const PORT_GENERATION_STEP: u32 = 4;

/// ipc_entry generation tag: the low two bits value (3).
pub const PORT_GENERATION_TAG: u32 = 3;

// ---------------------------------------------------------------------------
// Mach message: header types, options, descriptors, errors
// ---------------------------------------------------------------------------

/// The null port name.
pub const MACH_PORT_NULL: u32 = 0;

/// Message header msgh_bits: move receive right.
pub const MACH_TYPE_MOVE_RECEIVE: u32 = 16;

/// Message header msgh_bits: move send right.
pub const MACH_TYPE_MOVE_SEND: u32 = 17;

/// Message header msgh_bits: move send-once right.
pub const MACH_TYPE_MOVE_SEND_ONCE: u32 = 18;

/// Message header msgh_bits: copy send right.
pub const MACH_TYPE_COPY_SEND: u32 = 19;

/// Message header msgh_bits: make send right.
pub const MACH_TYPE_MAKE_SEND: u32 = 20;

/// Message header msgh_bits: make send-once right.
pub const MACH_TYPE_MAKE_SEND_ONCE: u32 = 21;

/// Notify ID: send-once notification (notify.h).
pub const MACH_NOTIFY_SEND_ONCE: u32 = 71;

/// Shift of the disposition field inside a descriptor (type+disposition).
pub const MACH_DESCRIPTOR_DISPOSITION_SHIFT: u32 = 16;

/// Message header msgh_bits: complex message (descriptors present).
pub const MACH_MSG_COMPLEX: u32 = 0x8000_0000;

/// Shift of the local (same-task) copy bits in msgh_bits.
pub const MACH_MSG_LOCAL_BITS_SHIFT: u32 = 8;

/// Descriptor type: port right.
pub const MACH_MSG_PORT_DESCRIPTOR: u32 = 0;

/// Descriptor type: out-of-line memory.
pub const MACH_MSG_OOL_DESCRIPTOR: u32 = 1;

/// Descriptor type: out-of-line port array.
pub const MACH_MSG_OOL_PORTS_DESCRIPTOR: u32 = 2;

/// Descriptor type: out-of-line volatile memory.
pub const MACH_MSG_OOL_VOLATILE_DESCRIPTOR: u32 = 3;

/// OOL descriptor copy: virtual copy semantics.
pub const MACH_MSG_VIRTUAL_COPY: u32 = 1;

/// mach_msg option: send a message.
pub const MACH_SEND_MSG: u32 = 1;

/// mach_msg option: receive a message.
pub const MACH_RCV_MSG: u32 = 2;

/// mach_msg option: receive even if buffer too small (MACH_RCV_LARGE).
pub const MACH_RCV_LARGE: u32 = 4;

/// mach_msg option: send timeout.
pub const MACH_SEND_TIMEOUT: u32 = 0x10;

/// mach_msg option: receive timeout.
pub const MACH_RCV_TIMEOUT: u32 = 0x100;

/// mach_msg option: report send override.
pub const MACH_SEND_OVERRIDE: u32 = 0x20;

/// mach_msg option: no importance boost on send.
pub const MACH_SEND_NOIMPORTANCE: u32 = 0x4_0000;

/// mach_msg option: sync override of send.
pub const MACH_SEND_SYNC_OVERRIDE: u32 = 0x10_0000;

/// mach_msg option: propagate QoS on send.
pub const MACH_SEND_PROPAGATE_QOS: u32 = 0x20_0000;

/// mach_msg receive option: participate in sync wait.
pub const MACH_RCV_SYNC_WAIT: u32 = 0x4000;

/// mach_msg receive option: report identity on large receive.
pub const MACH_RCV_LARGE_IDENTITY: u32 = 8;

/// mach_msg receive option: voucher movement.
pub const MACH_RCV_VOUCHER: u32 = 0x800;

/// Mask of requested trailer size bits in the receive option word.
pub const MACH_RCV_TRAILER_MASK: u32 = 0x0f00_0000;

/// Shift of the trailer size bits in the receive option word.
pub const MACH_RCV_TRAILER_SHIFT: u32 = 24;

/// Maximum trailer element (number of trailer types).
pub const MACH_RCV_TRAILER_MAX: u32 = 4;

/// kern_return_t: invalid message data on send.
pub const MACH_SEND_INVALID_DATA: u32 = 0x1000_0002;

/// kern_return_t: invalid destination port on send.
pub const MACH_SEND_INVALID_DEST: u32 = 0x1000_0003;

/// kern_return_t: send timed out.
pub const MACH_SEND_TIMED_OUT: u32 = 0x1000_0004;

/// kern_return_t: message too small to hold a valid header.
pub const MACH_SEND_MSG_TOO_SMALL: u32 = 0x1000_0008;

/// kern_return_t: invalid reply port on send.
pub const MACH_SEND_INVALID_REPLY: u32 = 0x1000_0009;

/// kern_return_t: message too large.
pub const MACH_SEND_TOO_LARGE: u32 = 0x1000_000e;

/// kern_return_t: invalid message header.
pub const MACH_SEND_INVALID_HEADER: u32 = 0x1000_0010;

/// kern_return_t: invalid send option bits.
pub const MACH_SEND_INVALID_OPTIONS: u32 = 0x1000_0013;

/// kern_return_t: invalid receive name.
pub const MACH_RCV_INVALID_NAME: u32 = 0x1000_4002;

/// kern_return_t: receive timed out.
pub const MACH_RCV_TIMED_OUT: u32 = 0x1000_4003;

/// kern_return_t: buffer too small for received message.
pub const MACH_RCV_TOO_LARGE: u32 = 0x1000_4004;

/// kern_return_t: receive interrupted.
pub const MACH_RCV_INTERRUPTED: u32 = 0x1000_4005;

/// kern_return_t: invalid receive notification port.
pub const MACH_RCV_INVALID_NOTIFY: u32 = 0x1000_4007;

/// kern_return_t: invalid received message data.
pub const MACH_RCV_INVALID_DATA: u32 = 0x1000_4008;

/// kern_return_t: receive port died.
pub const MACH_RCV_PORT_DIED: u32 = 0x1000_4009;

/// kern_return_t: invalid receive arguments.
pub const MACH_RCV_INVALID_ARGUMENTS: u32 = 0x1000_4013;

// ---------------------------------------------------------------------------
// MIG subroutine IDs (observed legacy iOS ABI)
// ---------------------------------------------------------------------------

/// MIG subsystem: port (mach_port.defs base id 3200 + 1).
pub const MIG_PORT_TYPE: u32 = 3201;

/// MIG subroutine: host_info.
pub const MIG_HOST_INFO: u32 = 200;

/// MIG subroutine: host_get_clock_service.
pub const MIG_HOST_GET_CLOCK: u32 = 206;

/// MIG subroutine: clock_get_time.
pub const MIG_CLOCK_GET_TIME: u32 = 1000;

/// MIG subroutine: task_info.
pub const MIG_TASK_INFO: u32 = 3405;

/// MIG subroutine: task_get_special_port.
pub const MIG_TASK_GET_SPECIAL_PORT: u32 = 3409;

/// MIG subroutine: semaphore_create.
pub const MIG_SEMAPHORE_CREATE: u32 = 3418;

/// Offset from a MIG routine id to its reply id.
pub const MIG_REPLY_ID_OFFSET: u32 = 100;

/// MIG "bad id" marker for unmatched subsystems (as i32, -303).
pub const MIG_BAD_ID: i32 = -303;

/// BackBoardServices MIG: BKSGetMainScreenInfo.
pub const MIG_BKS_GET_MAIN_SCREEN_INFO: u32 = 600_1004;

/// BackBoardServices MIG: BKSGetMainScreenInfoExtended.
pub const MIG_BKS_GET_MAIN_SCREEN_INFO_EXTENDED: u32 = 600_1009;

/// CoreAnimation MIG: CACopyDisplayList.
pub const MIG_CA_COPY_DISPLAY_LIST: u32 = 40_231;

/// CoreAnimation MIG: CACopyDisplayProperties.
pub const MIG_CA_COPY_DISPLAY_PROPERTIES: u32 = 40_232;

// ---------------------------------------------------------------------------
// Service-level ABI (flavors, counts, AMFI/sandbox mac_syscall ops)
// ---------------------------------------------------------------------------

/// host_info flavor: HOST_PRIORITY_INFO.
pub const HOST_PRIORITY_INFO: u32 = 5;

/// host_info: HOST_PRIORITY_INFO message count.
pub const HOST_PRIORITY_INFO_COUNT: u32 = 8;

/// task_info flavor: TASK_AUDIT_TOKEN.
pub const TASK_AUDIT_TOKEN: u32 = 15;

/// audit_token_t word count.
pub const AUDIT_TOKEN_WORDS: u32 = 8;

/// task_get_special_port: TASK_BOOTSTRAP_PORT.
pub const TASK_BOOTSTRAP_PORT: u32 = 4;

/// task_get_special_port: TASK_DEBUG_CONTROL_PORT.
pub const TASK_DEBUG_CONTROL_PORT: u32 = 10;

/// Clock service id: system clock.
pub const CLOCK_SYSTEM: u32 = 0;

/// Clock service id: calendar clock.
pub const CLOCK_CALENDAR: u32 = 1;

/// __mac_syscall policy id: AMFI dyld policy.
pub const AMFI_DYLD_POLICY: u32 = 90;

/// __mac_syscall op: sandbox_check_common's SANDBOX_CHECK.
pub const SANDBOX_CHECK: u32 = 2;

/// AMFI dyld policy allow bit: at()-style path syscalls.
pub const AMFI_ALLOW_AT_PATHS: u32 = 1;

/// AMFI dyld policy allow bit: DYLD environment variables.
pub const AMFI_ALLOW_PATH_ENV: u32 = 2;

/// AMFI dyld policy allow bit: custom dyld cache.
pub const AMFI_ALLOW_CUSTOM_CACHE: u32 = 4;

/// AMFI dyld policy allow bit: fallback library paths.
pub const AMFI_ALLOW_FALLBACK_PATHS: u32 = 8;

/// AMFI dyld policy allow bit: printing the environment.
pub const AMFI_ALLOW_PRINT_ENV: u32 = 16;

/// AMFI dyld policy allow bit: failed insert (into the shared cache).
pub const AMFI_ALLOW_FAILED_INSERT: u32 = 32;

// ---------------------------------------------------------------------------
// csops/csops_audittoken operations (bsd/sys/codesign.h)
// ---------------------------------------------------------------------------

/// CS_OPS_STATUS.
pub const CS_OPS_STATUS: u32 = 0;

/// CS_OPS_ENTITLEMENTS_BLOB.
pub const CS_OPS_ENTITLEMENTS_BLOB: u32 = 7;

/// CS_OPS_DER_ENTITLEMENTS_BLOB.
pub const CS_OPS_DER_ENTITLEMENTS_BLOB: u32 = 16;

// ---------------------------------------------------------------------------
// Commpage offsets (arm/cpu_capabilities.h layout)
// ---------------------------------------------------------------------------

/// Commpage: version field offset.
pub const COMM_VERSION: u32 = 0x1e;

/// Commpage: 64-bit CPU capabilities offset (cpufeatures for arm64).
pub const COMM_CPU_CAPABILITIES64: u32 = 0x10;

/// Commpage: 32-bit CPU capabilities offset.
pub const COMM_CPU_CAPABILITIES: u32 = 0x20;

/// Commpage: 32-bit user page shift offset.
pub const COMM_USER_PAGE_SHIFT_32: u32 = 0x24;

/// Commpage: 64-bit user page shift offset (0x25; 14 on 16K systems).
pub const COMM_USER_PAGE_SHIFT_64: u32 = 0x25;

/// Commpage: cache line size offset.
pub const COMM_CACHE_LINE_SIZE: u32 = 0x26;

/// Commpage: active CPU count offset.
pub const COMM_ACTIVE_CPUS: u32 = 0x34;

/// Commpage: physical CPU count offset.
pub const COMM_PHYSICAL_CPUS: u32 = 0x35;

/// Commpage: logical CPU count offset.
pub const COMM_LOGICAL_CPUS: u32 = 0x36;

/// Commpage: kernel page shift offset.
pub const COMM_KERNEL_PAGE_SHIFT: u32 = 0x37;

/// Commpage: memory size offset.
pub const COMM_MEMORY_SIZE: u32 = 0x38;

/// Commpage: CPU count shift used when packing counts into one word.
pub const COMM_CPU_COUNT_SHIFT: u32 = 16;

// ---------------------------------------------------------------------------
// Ullock (ulock_wait/ulock_wake operation word)
// ---------------------------------------------------------------------------

/// UL op: compare-and-wait.
pub const UL_COMPARE_AND_WAIT: u32 = 1;

/// UL op: unfair lock.
pub const UL_UNFAIR_LOCK: u32 = 2;

/// UL op flag: wake all waiters.
pub const UL_WAKE_ALL: u32 = 0x100;

/// UL op flag: allow wake by non-owner.
pub const UL_WAKE_ALLOW_NON_OWNER: u32 = 0x400;

/// UL op flag: workq data contention waiter.
pub const UL_WAIT_WORKQ_DATA_CONTENTION: u32 = 0x1_0000;

/// UL op flag: waiter is at a cancel point.
pub const UL_WAIT_CANCEL_POINT: u32 = 0x2_0000;

/// UL op flag: adaptive spin allowed.
pub const UL_WAIT_ADAPTIVE_SPIN: u32 = 0x4_0000;

/// UL op flag: return 0 instead of errno on the wait paths.
pub const UL_NO_ERRNO: u32 = 0x100_0000;

/// Mask of the operation bits inside the ulock operation word.
pub const UL_OPERATION_MASK: u32 = 0xff;

// ---------------------------------------------------------------------------
// pthread start (bsdthread_create flags word)
// ---------------------------------------------------------------------------

/// bsdthread_create flag: custom stack supplied.
pub const PTHREAD_START_CUSTOM: u32 = 0x0100_0000;

/// bsdthread_create flag: QoS fields present.
pub const PTHREAD_START_QOS: u32 = 0x0800_0000;

/// bsdthread_create flag: TSD set requested.
pub const PTHREAD_START_TSD_SET: u32 = 0x1000_0000;

/// bsdthread_create: priority field mask.
pub const PTHREAD_PRIORITY_MASK: u32 = 0x00ff_ffff;

/// bsdthread_create: relative priority field mask.
pub const PTHREAD_RELATIVE_PRIORITY_MASK: u32 = 255;

/// bsdthread_create: QoS field shift.
pub const PTHREAD_QOS_SHIFT: u32 = 8;

/// bsdthread_create: QoS field mask.
pub const PTHREAD_QOS_MASK: u32 = 0xffff;

/// Default QoS bit encoding inside the priority field.
pub const PTHREAD_DEFAULT_QOS_BITS: u32 = 8;

/// Value for zero relative priority.
pub const PTHREAD_ZERO_RELATIVE_PRIORITY: u32 = 255;

// ---------------------------------------------------------------------------
// Workqueue / bsdthread_register / workq_kernreturn ABI
// ---------------------------------------------------------------------------

/// bsdthread_register feature: dispatch.
pub const PTHREAD_FEATURE_DISPATCH: u32 = 0x01;

/// bsdthread_register feature: fine-grained priority.
pub const PTHREAD_FEATURE_FINEPRIO: u32 = 0x02;

/// bsdthread_register feature: workq_ctl.
pub const PTHREAD_FEATURE_CTL: u32 = 0x04;

/// bsdthread_register feature: set-self.
pub const PTHREAD_FEATURE_SETSELF: u32 = 0x08;

/// bsdthread_register feature: maintenance thread.
pub const PTHREAD_FEATURE_MAINTENANCE: u32 = 0x10;

/// bsdthread_register feature: kevent.
pub const PTHREAD_FEATURE_KEVENT: u32 = 0x40;

/// bsdthread_register feature: workloop.
pub const PTHREAD_FEATURE_WORKLOOP: u32 = 0x80;

/// bsdthread_register default feature set bit.
pub const PTHREAD_FEATURE_DEFAULT: u32 = 0x4000_0000;

/// workq_kernreturn option: normal worker return.
pub const WQ_RETURN: u32 = 0x004;

/// workq_kernreturn option: kevent worker return.
pub const WQ_KEVENT_RETURN: u32 = 0x040;

/// workq_kernreturn option: workloop worker return.
pub const WQ_WORKLOOP_RETURN: u32 = 0x100;

/// workq_kernreturn option: new SPI support.
pub const WQ_NEWSPISUPP: u32 = 0x010;

/// workq_kernreturn option: request threads.
pub const WQ_REQTHREADS: u32 = 0x020;

/// workq_kernreturn option: set up dispatch.
pub const WQ_SETUP_DISPATCH: u32 = 0x400;

/// workq_kernreturn option: event manager priority.
pub const WQ_EVENT_MANAGER_PRIORITY: u32 = 0x080;

/// workq_kernreturn option: should narrow.
pub const WQ_SHOULD_NARROW: u32 = 0x200;

/// workq_kernreturn option: QoS in prio field.
pub const WQ_PRIO_QOS: u32 = 0x4000;

/// workq_kernreturn option: overcommit.
pub const WQ_OVERCOMMIT: u32 = 0x1_0000;

/// workq_kernreturn option: new SPI.
pub const WQ_NEWSPI: u32 = 0x4_0000;

/// workq_kernreturn option: kevent.
pub const WQ_KEVENT: u32 = 0x8_0000;

/// workq_kernreturn option: event manager.
pub const WQ_EVENT_MANAGER: u32 = 0x10_0000;

/// workq_kernreturn option: TSD set.
pub const WQ_TSD_SET: u32 = 0x20_0000;

/// workq_kernreturn option: workloop.
pub const WQ_WORKLOOP: u32 = 0x40_0000;

/// workq_kernreturn option: reuse worker.
pub const WQ_REUSE: u32 = 0x2_0000;

/// workq_kernreturn special return value: exit, no kevents (as i32, -1).
pub const WQ_EXIT_NKEVENT: i32 = -1;

/// Priority flag: overcommit.
pub const PRIORITY_OVERCOMMIT: u32 = 0x8000_0000;

/// Priority flag: fallback priority.
pub const PRIORITY_FALLBACK: u32 = 0x0400_0000;

/// workq_ctl command: set QoS.
pub const CTL_SET_QOS: u32 = 0x10;

/// workq_ctl command: get QoS.
pub const CTL_GET_QOS: u32 = 0x20;

/// workq_ctl command: set self attributes.
pub const CTL_SET_SELF: u32 = 0x100;

/// workq_ctl command: max parallelism query.
pub const CTL_MAX_PARALLELISM: u32 = 0x800;

/// workq_ctl set-self sub-op: QoS.
pub const SET_SELF_QOS: u32 = 1;

/// workq_ctl set-self sub-op: voucher.
pub const SET_SELF_VOUCHER: u32 = 2;

/// workq_ctl set-self sub-op: fixed priority.
pub const SET_SELF_FIXED: u32 = 4;

/// workq_ctl set-self sub-op: timeshare priority.
pub const SET_SELF_TIMESHARE: u32 = 8;

// ---------------------------------------------------------------------------
// kevent (bsd/sys/event.h): filters, flags, kevent_qos options, notes
// ---------------------------------------------------------------------------

/// EVFILT_READ.
pub const EVFILT_READ: i32 = -1;

/// EVFILT_WRITE.
pub const EVFILT_WRITE: i32 = -2;

/// EVFILT_TIMER.
pub const EVFILT_TIMER: i32 = -7;

/// EVFILT_USER.
pub const EVFILT_USER: i32 = -10;

/// EVFILT_MEMORYSTATUS.
pub const EVFILT_MEMORYSTATUS: i32 = -14;

/// EVFILT_MACHPORT.
pub const EVFILT_MACHPORT: i32 = -8;

/// EVFILT_WORKLOOP.
pub const EVFILT_WORKLOOP: i32 = -17;

/// EV_ADD.
pub const EV_ADD: u32 = 1;

/// EV_DELETE.
pub const EV_DELETE: u32 = 2;

/// EV_ENABLE.
pub const EV_ENABLE: u32 = 4;

/// EV_DISABLE.
pub const EV_DISABLE: u32 = 8;

/// EV_ONESHOT.
pub const EV_ONESHOT: u32 = 0x10;

/// EV_CLEAR.
pub const EV_CLEAR: u32 = 0x20;

/// EV_RECEIPT.
pub const EV_RECEIPT: u32 = 0x40;

/// EV_DISPATCH.
pub const EV_DISPATCH: u32 = 0x80;

/// EV_UDATA_SPECIFIC.
pub const EV_UDATA_SPECIFIC: u32 = 0x100;

/// EV_VANISHED (returned in flags).
pub const EV_VANISHED: u32 = 0x200;

/// EV_ERROR (returned in flags).
pub const EV_ERROR: u32 = 0x4000;

/// EV_EOF (returned in flags).
pub const EV_EOF: u32 = 0x8000;

/// kevent_id/kevent_qos flag: immediate.
pub const KEVENT_IMMEDIATE: u32 = 1;

/// kevent_id/kevent_qos flag: error events.
pub const KEVENT_ERROR_EVENTS: u32 = 2;

/// kevent_id/kevent_qos flag: stack data.
pub const KEVENT_STACK_DATA: u32 = 8;

/// kevent_id/kevent_qos flag: workq.
pub const KEVENT_WORKQ: u32 = 0x20;

/// kevent_id/kevent_qos flag: workloop.
pub const KEVENT_WORKLOOP: u32 = 0x400;

/// kevent_id/kevent_qos flag: entry must exist.
pub const KEVENT_MUST_EXIST: u32 = 0x2_0000;

/// kevent_id/kevent_qos flag: entry must not exist.
pub const KEVENT_MUST_NOT_EXIST: u32 = 0x4_0000;

/// NOTE_TRIGGER.
pub const NOTE_TRIGGER: u32 = 0x0100_0000;

/// NOTE_FFAND.
pub const NOTE_FFAND: u32 = 0x4000_0000;

/// NOTE_FFOR.
pub const NOTE_FFOR: u32 = 0x8000_0000;

/// NOTE_FFCOPY.
pub const NOTE_FFCOPY: u32 = 0xc000_0000;

/// NOTE_FFCTRLMASK.
pub const NOTE_FFCTRLMASK: u32 = 0xc000_0000;

/// NOTE_FFLAGSMASK.
pub const NOTE_FFLAGSMASK: u32 = 0x00ff_ffff;

/// NOTE_SECONDS.
pub const NOTE_SECONDS: u32 = 1;

/// NOTE_USECONDS.
pub const NOTE_USECONDS: u32 = 2;

/// NOTE_NSECONDS.
pub const NOTE_NSECONDS: u32 = 4;

/// NOTE_ABSOLUTE.
pub const NOTE_ABSOLUTE: u32 = 8;

/// NOTE_LEEWAY.
pub const NOTE_LEEWAY: u32 = 0x10;

/// NOTE_MACH_CONTINUOUS_TIME.
pub const NOTE_MACH_CONTINUOUS_TIME: u32 = 0x80;

/// NOTE_MACHTIME.
pub const NOTE_MACHTIME: u32 = 0x100;

// ---------------------------------------------------------------------------
// Memory pressure / workloop notes
// ---------------------------------------------------------------------------

/// Jetsam level: normal.
pub const MEMORY_NORMAL: u32 = 1;

/// Jetsam level: warning.
pub const MEMORY_WARN: u32 = 2;

/// Jetsam level: critical.
pub const MEMORY_CRITICAL: u32 = 4;

/// Jetsam level: per-process warning.
pub const MEMORY_PROC_WARN: u32 = 0x10;

/// Jetsam level: per-process critical.
pub const MEMORY_PROC_CRITICAL: u32 = 0x20;

/// memorystatus control status mask.
pub const MEMORY_MSL_STATUS: u32 = 0xf000_0000;

/// Workloop note: thread request.
pub const NOTE_WL_THREAD_REQUEST: u32 = 1;

/// Workloop note: synchronous wait.
pub const NOTE_WL_SYNC_WAIT: u32 = 4;

/// Workloop note: synchronous wake.
pub const NOTE_WL_SYNC_WAKE: u32 = 8;

/// Workloop note: command mask.
pub const NOTE_WL_COMMAND_MASK: u32 = 0x8000_000f;

/// Workloop note: update QoS.
pub const NOTE_WL_UPDATE_QOS: u32 = 0x10;

/// Workloop note: end ownership.
pub const NOTE_WL_END_OWNERSHIP: u32 = 0x20;

/// Workloop note: discover owner.
pub const NOTE_WL_DISCOVER_OWNER: u32 = 0x80;

/// Workloop note: ignore ESTALE.
pub const NOTE_WL_IGNORE_ESTALE: u32 = 0x100;

/// Workloop servicer attribute: address.
pub const WL_ADDR: u32 = 1;

/// Workloop servicer attribute: mask.
pub const WL_MASK: u32 = 2;

/// Workloop servicer attribute: value.
pub const WL_VALUE: u32 = 3;

// ---------------------------------------------------------------------------
// Mutex/voucher (libpthread internal + bank entitlements)
// ---------------------------------------------------------------------------

/// Mutex policy field shift inside the pthread mutex option word.
pub const MUTEX_POLICY_SHIFT: u32 = 6;

/// Mutex policy field mask.
pub const MUTEX_POLICY_MASK: u32 = 7;

/// Mutex policy: first-fit.
pub const MUTEX_FIRSTFIT: u32 = 2;

/// Mutex option: shared.
pub const MUTEX_SHARED: u32 = 0x10;

/// Voucher key for the bank.
pub const VOUCHER_KEY_BANK: u32 = 3;

/// Voucher MIG command: bank create (VoucherBankCreate).
pub const VOUCHER_BANK_CREATE: u32 = 610;

// ---------------------------------------------------------------------------
// Activity IDs (osfmk/kern/coalition.h era)
// ---------------------------------------------------------------------------

/// Maximum number of activity IDs per mach_generate_activity_id call.
pub const ACTIVITY_ID_COUNT_MAX: u32 = 16;

// ---------------------------------------------------------------------------
// proc_info flavors
// ---------------------------------------------------------------------------

/// proc_info call number: PIDINFO.
pub const PROC_CALL_PIDINFO: u32 = 2;

/// proc_info PIDINFO flavor: PROC_PIDUNIQUEIDENTIFIERINFO.
pub const PROC_PIDUNIQUEIDENTIFIERINFO: u32 = 17;

// ---------------------------------------------------------------------------
// fcntl commands and record-lock types (bsd/sys/fcntl.h)
// ---------------------------------------------------------------------------

/// F_GETLK.
pub const F_GETLK: u32 = 7;

/// F_SETLK.
pub const F_SETLK: u32 = 8;

/// F_SETLKW.
pub const F_SETLKW: u32 = 9;

/// F_GETPATH.
pub const F_GETPATH: u32 = 50;

/// F_OFD_SETLK.
pub const F_OFD_SETLK: u32 = 90;

/// F_OFD_SETLKW.
pub const F_OFD_SETLKW: u32 = 91;

/// F_OFD_GETLK.
pub const F_OFD_GETLK: u32 = 92;

/// F_ADDFILESIGS_RETURN.
pub const F_ADDFILESIGS_RETURN: u32 = 97;

/// F_CHECK_LV.
pub const F_CHECK_LV: u32 = 98;

/// flock type: shared/read lock.
pub const F_RDLCK: u32 = 1;

/// flock type: unlock.
pub const F_UNLCK: u32 = 2;

/// flock type: exclusive/write lock.
pub const F_WRLCK: u32 = 3;

// ---------------------------------------------------------------------------
// Resource limits (bsd/sys/resource.h) — LP64 rlim_t wire values
// ---------------------------------------------------------------------------

/// RLIMIT_CPU.
pub const RLIMIT_CPU: u32 = 0;

/// RLIMIT_FSIZE.
pub const RLIMIT_FSIZE: u32 = 1;

/// RLIMIT_DATA.
pub const RLIMIT_DATA: u32 = 2;

/// RLIMIT_STACK.
pub const RLIMIT_STACK: u32 = 3;

/// RLIMIT_CORE.
pub const RLIMIT_CORE: u32 = 4;

/// RLIMIT_AS.
pub const RLIMIT_AS: u32 = 5;

/// RLIMIT_MEMLOCK.
pub const RLIMIT_MEMLOCK: u32 = 6;

/// RLIMIT_NPROC.
pub const RLIMIT_NPROC: u32 = 7;

/// RLIMIT_NOFILE.
pub const RLIMIT_NOFILE: u32 = 8;

/// RLIMIT_COUNT (number of resource limits).
pub const RLIMIT_COUNT: u32 = 9;

/// RLIM POSIX flag bit.
pub const RLIMIT_POSIX_FLAG: u32 = 0x1000;

/// RLIM_INFINITY wire value.
pub const RLIM_INFINITY: u64 = 0x7fff_ffff_ffff_ffff;

// ---------------------------------------------------------------------------
// Bootstrap (launchd liblaunch / bootstrap{,_priv}.h)
// ---------------------------------------------------------------------------

/// Maximum bootstrap service name length.
pub const BOOTSTRAP_NAME_MAX: u32 = 128;

/// Bootstrap flag: per-pid service.
pub const BOOTSTRAP_PER_PID_SERVICE: u32 = 1;

// ---------------------------------------------------------------------------
// Documented wire sizes of remaining small structs (darwin-abi.h)
// ---------------------------------------------------------------------------

/// sizeof(struct darwin_msg_vector) — mach_msg2 send/receive vector.
pub const MSG_VECTOR_SIZE: usize = 24;

/// sizeof(struct darwin_msg_aux_header) — mach_msg2 auxiliary header.
pub const MSG_AUX_HEADER_SIZE: usize = 8;

/// sizeof(struct darwin_pthread_registration) — bsdthread_register payload
/// (packed).
pub const PTHREAD_REGISTRATION_SIZE: usize = 48;

/// sizeof(struct darwin_proc_unique) — PROC_PIDUNIQUEIDENTIFIERINFO payload.
pub const PROC_UNIQUE_SIZE: usize = 56;

/// sizeof(struct darwin_context_trailer) — packed, 4-byte aligned.
pub const CONTEXT_TRAILER_SIZE: usize = 60;

/// sizeof(struct darwin_port_options) — mach_port_construct options.
pub const PORT_OPTIONS_SIZE: usize = 24;

/// sizeof(struct darwin_flock) (field `type` at offset 20).
pub const FLOCK_SIZE: usize = 24;

/// offsetof(struct darwin_flock, type).
pub const FLOCK_TYPE_OFFSET: usize = 20;

/// sizeof(struct darwin_fsignatures) — F_ADDFILESIGS_RETURN payload.
pub const FSIGNATURES_SIZE: usize = 24;

/// sizeof(struct darwin_workq_dispatch_config) — workq metadata v1/v2.
pub const WORKQ_DISPATCH_CONFIG_SIZE: usize = 24;

/// sizeof(struct darwin_fchecklv) — F_CHECK_LV payload.
pub const FCHECKLV_SIZE: usize = 24;

/// sizeof(struct darwin_voucher_recipe) — voucher attribute recipe entry.
pub const VOUCHER_RECIPE_SIZE: usize = 16;

/// sizeof(struct darwin_timeval) — LP64 timeval wire layout.
pub const TIMEVAL_SIZE: usize = 16;

/// sizeof(struct darwin_rlimit) — two u64 rlim_t values.
pub const RLIMIT_SIZE: usize = 16;

/// sizeof(struct darwin_statfs64) — computed LP64 inode64 layout.
pub const STATFS64_SIZE: usize = 2168;

/// Fixed prefix of struct darwin_dirent64 (name[] follows at this offset).
pub const DIRENT64_FIXED_SIZE: usize = 21;
