//! errno — Darwin BSD errno values and Mach kern_return codes.
//!
//! Guests see these values in x0 (with the carry flag `0x20000000` set) when
//! a BSD syscall fails. They are Darwin values and deliberately differ from
//! host Linux errno in several places (e.g. Darwin EAGAIN = 35, ENOSYS = 78,
//! ELAST ~= 106). The kern_return table covers only the codes the distilled
//! header documents; Mach message send/receive error codes (the
//! `0x1000xxxx` band) live in `abi` under the Mach message constants.
//!
//! Source: arlinux-xnu src/darwin-abi.h (darwin_errno, darwin_kern_return,
//! darwin_bootstrap enums)
//! Source: xnu bsd/sys/errno.h, osfmk/mach/kern_return.h (upstream identity)

/// Darwin BSD errno values as `(number, name)`, ascending.
pub const ERRNOS: &[(u32, &str)] = &[
    (1, "EPERM"),
    (2, "ENOENT"),
    (3, "ESRCH"),
    (4, "EINTR"),
    (5, "EIO"),
    (6, "ENXIO"),
    (7, "E2BIG"),
    (8, "ENOEXEC"),
    (9, "EBADF"),
    (10, "ECHILD"),
    (12, "ENOMEM"),
    (13, "EACCES"),
    (14, "EFAULT"),
    (16, "EBUSY"),
    (17, "EEXIST"),
    (18, "EXDEV"),
    (19, "ENODEV"),
    (20, "ENOTDIR"),
    (21, "EISDIR"),
    (22, "EINVAL"),
    (23, "ENFILE"),
    (24, "EMFILE"),
    (27, "EFBIG"),
    (28, "ENOSPC"),
    (29, "ESPIPE"),
    (30, "EROFS"),
    (31, "EMLINK"),
    (32, "EPIPE"),
    (33, "EDOM"),
    (34, "ERANGE"),
    (35, "EAGAIN"),
    (43, "EPROTONOSUPPORT"),
    (44, "ESOCKTNOSUPPORT"),
    (45, "ENOTSUP"),
    (47, "EAFNOSUPPORT"),
    (60, "ETIMEDOUT"),
    (63, "ENAMETOOLONG"),
    (70, "ESTALE"),
    (78, "ENOSYS"),
    (84, "EOVERFLOW"),
    (105, "EOWNERDEAD"),
];

/// Look up a Darwin errno name by number (binary search; the table is sorted).
pub fn name(num: u32) -> Option<&'static str> {
    ERRNOS
        .binary_search_by_key(&num, |e| e.0)
        .ok()
        .map(|i| ERRNOS[i].1)
}

/// Mach `kern_return_t` values documented by the distilled header, as
/// `(number, name)`, ascending. Codes not listed there (e.g.
/// KERN_PROTECTION_FAILURE = 2, KERN_NO_SPACE = 3's Mach sense,
/// KERN_MEMORY_ERROR = 10, MACH_SEND_INVALID_DEST = 0x10000003) are omitted
/// here; message-layer error codes live in `abi`.
pub const KERN_RETURNS: &[(u32, &str)] = &[
    (0, "KERN_SUCCESS"),
    (1, "KERN_INVALID_ADDRESS"),
    (3, "KERN_RESOURCE_SHORTAGE"),
    (4, "KERN_INVALID_ARGUMENT"),
    (5, "KERN_FAILURE"),
    (11, "KERN_ALREADY_IN_SET"),
    (12, "KERN_NOT_IN_SET"),
    (15, "KERN_INVALID_NAME"),
    (16, "KERN_INVALID_TASK"),
    (17, "KERN_INVALID_RIGHT"),
    (18, "KERN_INVALID_VALUE"),
    (19, "KERN_UREFS_OVERFLOW"),
    (46, "KERN_NOT_SUPPORTED"),
];

/// Look up a kern_return name by value (binary search; the table is sorted).
pub fn kern_return_name(num: u32) -> Option<&'static str> {
    KERN_RETURNS
        .binary_search_by_key(&num, |e| e.0)
        .ok()
        .map(|i| KERN_RETURNS[i].1)
}

/// Bootstrap (launchd) status codes returned through the bootstrap ports /
/// `bootstrap_check_in`-era interfaces, as `(number, name)`, ascending.
pub const BOOTSTRAP_STATUSES: &[(u32, &str)] = &[
    (1101, "BOOTSTRAP_NAME_IN_USE"),
    (1102, "BOOTSTRAP_UNKNOWN_SERVICE"),
    (1103, "BOOTSTRAP_SERVICE_ACTIVE"),
    (1105, "BOOTSTRAP_NO_MEMORY"),
];

/// Look up a bootstrap status name by value (binary search; sorted table).
pub fn bootstrap_status_name(num: u32) -> Option<&'static str> {
    BOOTSTRAP_STATUSES
        .binary_search_by_key(&num, |e| e.0)
        .ok()
        .map(|i| BOOTSTRAP_STATUSES[i].1)
}
