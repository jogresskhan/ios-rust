//! mach_traps — Mach trap table (negative x16 selector values).
//!
//! Guests enter the Mach side of the Darwin syscall ABI with `svc #0` and a
//! *negated* trap number in x16 (e.g. x16 = -31 for `mach_msg`). The table
//! below stores the number exactly as it appears in x16, so the key equals
//! the register value: the trap "mach_msg = 31" is stored as (-31, "mach_msg").
//!
//! The core entries come from the distilled ABI header's `darwin_mach_trap`
//! enum; the remaining well-known traps (task_for_pid, thread_switch,
//! mach_wait_until, ...) come from the vendored `osfmk/kern/syscall_sw.c`
//! mach trap table. `kern_invalid` filler slots are omitted. Note the vendored
//! darling kernel stubs traps 3/4/47 (`kern_invalid`), but upstream
//! xnu-7195.141.2 and the distilled header define 3 = mach_absolute_time,
//! 4 = mach_continuous_time and 47 = mach_msg2, which is what real iOS guests
//! call; this table follows the header.
//!
//! Source: arlinux-xnu src/darwin-abi.h (darwin_mach_trap enum)
//! Source: darling-xnu (Darwin 20.6.0 lineage) osfmk/kern/syscall_sw.c
//!         (mach_trap_table + mach_syscall_name_table)
//! Source: xnu-8796.141.3 mach/message.h (mach_msg2 routing hints, via the
//!         distilled header)

/// Mach traps as `(negative x16 value, name)`, ordered by the positive trap
/// number for readability; use [`name`] for lookups.
pub const MACH_TRAPS: &[(i32, &str)] = &[
    (-3, "mach_absolute_time"),
    (-4, "mach_continuous_time"),
    (-10, "mach_vm_allocate"),
    (-11, "mach_vm_purgable_control"),
    (-12, "mach_vm_deallocate"),
    (-13, "task_dyld_process_info_notify_get"),
    (-14, "mach_vm_protect"),
    (-15, "mach_vm_map"),
    (-16, "mach_port_allocate"),
    (-18, "mach_port_deallocate"),
    (-19, "mach_port_mod_refs"),
    (-20, "mach_port_move_member"),
    (-21, "mach_port_insert_right"),
    (-22, "mach_port_insert_member"),
    (-23, "mach_port_extract_member"),
    (-24, "mach_port_construct"),
    (-25, "mach_port_destruct"),
    (-26, "mach_reply_port"),
    (-27, "mach_thread_self"),
    (-28, "mach_task_self"),
    (-29, "mach_host_self"),
    (-31, "mach_msg"),
    (-32, "mach_msg_overwrite"),
    (-33, "semaphore_signal"),
    (-34, "semaphore_signal_all"),
    (-35, "semaphore_signal_thread"),
    (-36, "semaphore_wait"),
    (-37, "semaphore_wait_signal"),
    (-38, "semaphore_timedwait"),
    (-39, "semaphore_timedwait_signal"),
    (-40, "mach_port_get_attributes"),
    (-41, "mach_port_guard"),
    (-42, "mach_port_unguard"),
    (-43, "mach_generate_activity_id"),
    (-44, "task_name_for_pid"),
    (-45, "task_for_pid"),
    (-46, "pid_for_task"),
    (-47, "mach_msg2"),
    (-48, "macx_swapon"),
    (-49, "macx_swapoff"),
    (-50, "mach_special_reply_port"),
    (-51, "macx_triggers"),
    (-52, "macx_backing_store_suspend"),
    (-53, "macx_backing_store_recovery"),
    (-58, "pfz_exit"),
    (-59, "swtch_pri"),
    (-60, "swtch"),
    (-61, "thread_switch"),
    (-62, "clock_sleep"),
    (-70, "host_create_mach_voucher"),
    (-72, "mach_voucher_extract_attr_recipe"),
    (-76, "mach_port_type"),
    (-77, "mach_port_request_notification"),
    (-89, "mach_timebase_info"),
    (-90, "mach_wait_until"),
    (-91, "mk_timer_create"),
    (-92, "mk_timer_destroy"),
    (-93, "mk_timer_arm"),
    (-94, "mk_timer_cancel"),
    (-95, "mk_timer_arm_leeway"),
    (-96, "debug_control_port_for_pid"),
    (-100, "iokit_user_client_trap"),
];

/// Look up a Mach trap name by its (negative) x16 register value (linear
/// search; the table is ordered by positive trap number for readability).
pub fn name(num: i32) -> Option<&'static str> {
    MACH_TRAPS
        .iter()
        .find(|e| e.0 == num)
        .map(|e| e.1)
}

/// mach_msg2 (trap 47) `option` high-word routing hint: message is a
/// `mach_msg_vector_t` (send + receive descriptors).
pub const MACH64_MSG_VECTOR: u64 = 0x1_0000_0000;

/// mach_msg2 routing hint: send to a kernel object.
pub const MACH64_SEND_KOBJECT: u64 = 0x2_0000_0000;

/// mach_msg2 routing hint: send to a port set queue.
pub const MACH64_SEND_QUEUE: u64 = 0x4_0000_0000;

/// mach_msg2 routing hint: send to any receive right (dispatch-style).
pub const MACH64_SEND_ANY: u64 = 0x8_0000_0000;
