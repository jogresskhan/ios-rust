//! xnu — ARM64 Darwin (XNU) userspace ABI knowledge base.
//!
//! A dependency-free, std-only distillation of the Darwin syscall ABI that the
//! A13 CPU engine must understand to run XNU-era guests. It is a *knowledge
//! base*, not an implementation: static tables of BSD syscall numbers, Mach
//! trap numbers, errno/kern-return codes, wire-format structs, boot-args
//! layout and the early boot call order.
//!
//! # One-page ABI overview (ARM64 Darwin)
//!
//! * Entry: every userspace system call is `svc #0`
//!   (`D_ARM64_INSN_SVC_0 = 0xd4000001`). The selector lives in **x16**
//!   (`D_ARM64_SYSCALL_REGISTER = 16`); arguments go in x0..x7, further args
//!   on the stack.
//! * Sign convention: `x16 >= 0` selects the **BSD syscall table**
//!   (`bsd/kern/syscalls.master`); a *negative* x16 selects the **Mach trap
//!   table** (`osfmk/kern/syscall_sw.c`), stored here negated so the table
//!   key equals the register value the guest loads.
//! * `x16 == 0x80000000` (`PLATFORM_SYSCALL_TRAP_NO`) is the **platform
//!   syscall**: x0 then holds the platform operation
//!   (`PLATFORM_SET_TSD = 2`, `PLATFORM_GET_TSD = 3`).
//! * Return convention: x0 is the return value; for the BSD side, errors are
//!   signalled with the **carry bit** of CPSR (`D_ARM64_CARRY = 1 << 29`,
//!   i.e. `0x20000000`) and x0 holds the positive Darwin errno. Mach traps
//!   return a `kern_return_t` in x0 (negative error values in the
//!   `0x10000000` message-error band, e.g. `MACH_SEND_INVALID_DEST =
//!   0x10000003`).
//! * Numbers below are the raw guest values, never host Linux errno/syscall
//!   definitions.
//!
//! Sources (read-only reference repos):
//! - arlinux-xnu `src/darwin-abi.h` (distilled wire ABI, MIG IDs, commpage).
//! - darling-xnu (Darwin 20.6.0 lineage) `bsd/kern/syscalls.master`.
//! - darling-xnu `osfmk/kern/syscall_sw.c` (mach trap table + names).
//! - xnu-7195.141.2 (upstream identity of the Darwin 20.6 kernel build).
//! - darling-xnu `pexpert/pexpert/arm64/boot.h` and
//!   `pexpert/pexpert/arm/boot.h` (boot_args, Boot_Video).

pub mod abi;
pub mod boot;
pub mod errno;
pub mod mach_traps;
pub mod syscalls;

// Re-exports. The per-table lookup functions keep their module paths
// (syscalls::name, errno::name, mach_traps::name) because they collide as
// glob re-exports; everything else is re-exported at the crate root.
pub use abi::*;
pub use boot::*;
pub use errno::{
    BOOTSTRAP_STATUSES, ERRNOS, KERN_RETURNS, bootstrap_status_name, kern_return_name,
};
pub use mach_traps::{
    MACH64_MSG_VECTOR, MACH64_SEND_ANY, MACH64_SEND_KOBJECT, MACH64_SEND_QUEUE, MACH_TRAPS,
};
pub use syscalls::{
    AuditToken, AUDIT_TOKEN_SIZE, BSD_SYSCALLS, KeventQos, KEVENT_QOS_SIZE, Stat64, STAT64_SIZE,
    Timespec, TIMESPEC_SIZE,
};
