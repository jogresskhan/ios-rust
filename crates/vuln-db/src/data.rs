//! data — embedded knowledge-base tables: vuln entries, mitigation timeline, Frida notes, tool index.
//!
//! Curated distillation of public iOS security research: conference decks,
//! PoC writeups and the ansjdnakjdnajkd/iOS pentest cheatsheet tooling
//! index. Every string here is documentation and metadata, not exploit
//! code. Where an Apple advisory attribution is known to be misleading
//! (e.g. "IOKit" fixes that were really the ProvInfoIOKit driver or the
//! XNU kernel heap), both the advisory label and the real component are
//! recorded on the entry.
//!
//! Parity: 18 vuln-lineage entries (CVEs plus no-CVE design-bug and
//! Learning rows), 6 XNU zone-allocator mitigation notes (iOS 5..10),
//! 10 Frida/r2frida technique notes, 34 pentest tooling references.
//! Source: IdanBanani/iOS-Vulnerability-Research (conference decks/PoCs);
//! ansjdnakjdnajkd/iOS (pentest cheatsheet).

use crate::{FridaNote, MitigationNote, ComponentKind, ToolRef, VulnEntry};

pub const VULNS: &[VulnEntry] = &[
    // 1
    VulnEntry {
        id: "CVE-2019-7287",
        title: "ProvInfoIOKit userclient controlled-length memmove (OOB write)",
        component: "ProvInfoIOKit driver (kernel user client; Apple advisory said only 'IOKit')",
        kind: ComponentKind::IOKit,
        bug_class: "OOB memmove (controlled length)",
        affected: "iOS 12.1.3 and earlier (fixed 12.1.4)",
        primitive: "OOB write with attacker-controlled source, destination and length inside the kernel, reachable from any sandbox via IOServiceOpen on the provisioning-info driver.",
        summary: "The provisioning-info user client exposes a memmove-style external method whose length is taken verbatim from the caller while the buffers live in different kalloc zones: source in kalloc.512/kalloc.4096, destination in kalloc.8192, giving a straight out-of-bounds write past the destination allocation. Apple's advisory attributed the fix to 'IOKit' generically; patch-diffing the 12.1.4 kernelcache with Diaphora shows the real component is the ProvInfoIOKit driver. Esser rebuilt a working exploit from that diff at HITB GSEC 2019 ('Recreating an iOS 0day'), using heap feng shui with vm_map_copy_t, OOL_PORTS_DESCRIPTOR mach-port pointer overwrites and OSUnserializeXML/IOSurface sprays. On pre-iPhone 7 hardware the same bug also yields an immediate task-port leak.",
        techniques: &[
            "kernelcache patch-diffing with Diaphora",
            "heap feng shui via vm_map_copy_t sprays",
            "OOL_PORTS_DESCRIPTOR mach-port pointer overwrite",
            "OSUnserializeXML dictionary spray",
            "IOSurface allocation spray",
            "kalloc.512/4096 -> kalloc.8192 cross-zone write",
            "immediate task-port leak on pre-iPhone 7 devices",
        ],
        sources: &[
            "Esser, HITB GSEC 2019 'Recreating an iOS 0day'",
            "Apple security advisory iOS 12.1.4 (CVE-2019-7287)",
        ],
        year: 2019,
    },
    // 2
    VulnEntry {
        id: "CVE-2019-7286",
        title: "cfprefsd double xpc_release (UAF) via CFPreferencesOperation=5",
        component: "cfprefsd (XPC daemon)",
        kind: ComponentKind::Daemon,
        bug_class: "UAF / refcount (double xpc_release)",
        affected: "iOS 12.1.3 and earlier (fixed 12.1.4)",
        primitive: "use-after-free inside a privileged daemon: a crafted XPC dictionary skips the retain callback so the object is released twice, then the dangling object's ISA pointer is overwritten to gain PC control.",
        summary: "A crafted CFPreferencesOperation=5 XPC dictionary takes a path that never installs the retain callback, so the dictionary object is released twice and its backing memory is freed while the XPC runtime still holds a reference. The race window is widened by spraying XPC arrays to reclaim the freed slot deterministically. Following the Phrack 69 'nemo' Objective-C exploitation methodology, the freed object's fake ISA pointer is overwritten to redirect method dispatch, after which ROP runs inside cfprefsd. Found in the wild chained with CVE-2019-7287 and reproduced by ZecOps.",
        techniques: &[
            "crafted CFPreferencesOperation=5 XPC dictionary",
            "xpc_release refcount race",
            "XPC-array spray to widen the race window",
            "fake ISA pointer overwrite (Phrack 69 ObjC techniques)",
            "ROP inside cfprefsd",
            "ZecOps reproduction of the in-the-wild chain",
        ],
        sources: &[
            "ZecOps blog on the CVE-2019-7286/7287 in-the-wild chain",
            "Phrack 69 ('De Mysteriis Dom Jobsivs'), nemo — ObjC exploitation techniques",
            "Apple security advisory iOS 12.1.4 (CVE-2019-7286)",
        ],
        year: 2019,
    },
    // 3
    VulnEntry {
        id: "CVE-2018-4109",
        title: "AppleD5500 H.264 decoder signed/unsigned compare -> OOB memset 0x80 fill",
        component: "AppleD5500 H.264 decoder driver, driven from mediaserverd",
        kind: ComponentKind::IOKit,
        bug_class: "signed/unsigned compare -> OOB memset",
        affected: "iOS 11.2.x era (fixed 11.3)",
        primitive: "in-stream SPS re-injection bypasses the chroma_format_idc check, so the decoder memsets past the end of an IOSurface-backed reference buffer with a 0x80 fill.",
        summary: "The AppleD5500 decoder validates chroma_format_idc once per stream, but a crafted SPS re-injected mid-stream flips the field after the check, so the downstream signed/unsigned comparison accepts an out-of-range value and the decoder error path memsets reference data with a 0x80 fill past the end of an IOSurface. Yalu++'s RemapPage kernel-hooking methodology is cited for turning the mediaserverd-context corruption into a kernel foothold. The same class — sign-compare before length use — was demonstrated earlier in sharingd (CVE-2015-7006).",
        techniques: &[
            "in-stream SPS re-injection to bypass the chroma_format_idc check",
            "signed/unsigned compare confusion",
            "OOB memset with 0x80 fill onto an IOSurface",
            "IOSurface grooming",
            "Yalu++ RemapPage kernel hooking methodology",
            "shared class precedent: sharingd CVE-2015-7006",
        ],
        sources: &[
            "Yalu++ research writeups (Todesco)",
            "Apple security advisory iOS 11.3 (CVE-2018-4109)",
        ],
        year: 2018,
    },
    // 4
    VulnEntry {
        id: "CVE-2018-4095",
        title: "bluetoothd MIG stack-pointer shift in BTLocalDeviceGetPairedDevices",
        component: "bluetoothd MIG subsystem",
        kind: ComponentKind::Daemon,
        bug_class: "stack SP manipulation (unchecked MIG argument)",
        affected: "iOS 11.2.x (fixed 11.2.6)",
        primitive: "unchecked 32-bit MIG argument shifts the stack pointer via (&size - ((8*a5+15) & ~0xF)), giving controlled stack corruption in a root daemon reachable over XPC.",
        summary: "BTLocalDeviceGetPairedDevices computes a stack offset from an attacker-supplied argument without bounds checks: the address-of-size arithmetic (&size - ((8*a5+15) & ~0xF)) walks the stack pointer by a controlled amount, corrupting adjacent frames in the MIG dispatch path. Five sibling routines in the bluetoothd MIG subsystem shared the same pattern. The fix bounds the argument to a5 <= 0x100. bluetoothd exposes the subsystem over XPC, so the bug is reachable from the app sandbox without a Bluetooth entitlement.",
        techniques: &[
            "MIG argument validation audit",
            "stack-pointer arithmetic (&size - ((8*a5+15) & ~0xF))",
            "sibling-routine pattern analysis (5 related MIG routines)",
            "XPC client reachable from the app sandbox",
            "bounds fix a5 <= 0x100 (patch diff)",
        ],
        sources: &[
            "rani-i bluetoothdPoC writeup",
            "Apple security advisory iOS 11.2.6 (CVE-2018-4095)",
        ],
        year: 2018,
    },
    // 5
    VulnEntry {
        id: "CVE-2018-4087",
        title: "bluetoothd BTLocalDeviceAddCallbacks missing session validation",
        component: "bluetoothd MIG subsystem",
        kind: ComponentKind::Daemon,
        bug_class: "logic (missing session-token validation)",
        affected: "iOS 11.2.x (fixed 11.2.5)",
        primitive: "brute-force the 65536-token session-ID space, register an arbitrary callback pointer, and gain PC control when bluetoothd dispatches on the BluetoothBridge queue.",
        summary: "BTLocalDeviceAddCallbacks validates the caller-supplied session token by equality only, and the sender-ID space was small enough (65536 candidates) with no rate limiting, so a client can brute-force the token and register callbacks for another session. The registered callback is later invoked on the BluetoothBridge dispatch queue with attacker-influenced context, giving PC control inside the daemon. The fix moved sender identification to unguessable arc4random senderIDs bound per session.",
        techniques: &[
            "session-token brute force (65536 space)",
            "arbitrary callback registration",
            "dispatch-queue PC control (BluetoothBridge)",
            "senderID arc4random fix (patch diff)",
        ],
        sources: &[
            "rani-i bluetoothdPoC writeup",
            "Apple security advisory iOS 11.2.5 (CVE-2018-4087)",
        ],
        year: 2018,
    },
    // 6
    VulnEntry {
        id: "CVE-2021-1815",
        title: "cfprefsd arbitrary directory creation with controlled ownership",
        component: "cfprefsd (XPC daemon)",
        kind: ComponentKind::Daemon,
        bug_class: "logic/path traversal",
        affected: "iOS 14.4 and earlier (fixed 14.5)",
        primitive: "CFPreferencesDomain path traversal turns mkdirat+chown into arbitrary directory creation with controlled ownership — a pivot toward privileged locations such as /usr/local/etc/periodic/daily.",
        summary: "A domain key containing traversal components is passed from cfprefsd into mkdirat with an attacker-controlled path, after which chown applies attacker-influenced ownership, so a sandboxed client can materialize directories inside privileged trees. The /usr/local/etc/periodic/daily technique shows the payoff: create the directory a periodic job will later populate or execute from, planting persistence without code execution. The fix validates domain paths before filesystem mutation.",
        techniques: &[
            "CFPreferencesDomain key traversal",
            "mkdirat + chown as the primitive",
            "/usr/local/etc/periodic/daily planting technique",
            "sandboxed XPC client",
        ],
        sources: &[
            "Apple security advisory iOS 14.5 (CVE-2021-1815)",
            "cfprefsd research notes in the iOS-Vulnerability-Research corpus",
        ],
        year: 2021,
    },
    // 7
    VulnEntry {
        id: "CVE-2021-1740",
        title: "cfprefsd large-plist clonefile TOCTOU (snprintf 0x400 truncation)",
        component: "cfprefsd (XPC daemon)",
        kind: ComponentKind::Daemon,
        bug_class: "logic/TOCTOU",
        affected: "iOS 14.4 and earlier (fixed 14.5)",
        primitive: "snprintf 0x400 truncation makes the mktemp name predictable; a symlink race around the clonefile turns predictable temp paths into arbitrary file read/write.",
        summary: "When cloning a large plist, cfprefsd builds the temp name with snprintf into a 0x400 buffer; oversized path components truncate, mktemp's randomness collapses and the target name becomes predictable. The clonefile then follows a symlink planted at the predictable path, redirecting the copy into an arbitrary file — a read on the inbound clone, a write on the outbound one. Winning the TOCTOU is a straightforward symlink race once the name is predictable.",
        techniques: &[
            "snprintf 0x400 truncation",
            "predictable mktemp paths",
            "clonefile symlink race",
            "arbitrary file read and write from the sandbox",
        ],
        sources: &[
            "Apple security advisory iOS 14.5 (CVE-2021-1740)",
            "cfprefsd research notes in the iOS-Vulnerability-Research corpus",
        ],
        year: 2021,
    },
    // 8
    VulnEntry {
        id: "CVE-2021-1739",
        title: "cfprefsd write-then-rename symlink injection (arbitrary file rename)",
        component: "cfprefsd (XPC daemon)",
        kind: ComponentKind::Daemon,
        bug_class: "logic/symlink race",
        affected: "iOS 14.4 and earlier (fixed 14.5)",
        primitive: "a symlink planted as the middle path component redirects the write-then-rename sequence into an arbitrary file rename; the fix switches to renameat with a dir_fd.",
        summary: "cfprefsd writes the updated plist to a temp path and renames it into place without pinning the intermediate directory: a symlink placed as a middle path component survives between the write and the rename, so the rename lands on an attacker-chosen destination. The fix replaces the path-based rename with renameat against a directory file descriptor, removing the window. Encoded alongside its companion bug CVE-2020-27903 (storedownloadd NSXPC SSDownloadAsset arbitrary write, fixed iOS 14.2) as a matched pair of daemon path-handling escapes.",
        techniques: &[
            "symlink as middle path component",
            "write-then-rename TOCTOU",
            "renameat(dir_fd) hardening fix",
            "companion: CVE-2020-27903 storedownloadd SSDownloadAsset arbitrary write",
        ],
        sources: &[
            "Apple security advisory iOS 14.5 (CVE-2021-1739)",
            "Apple security advisory iOS 14.2 (CVE-2020-27903)",
        ],
        year: 2021,
    },
    // 9
    VulnEntry {
        id: "CVE-2015-5932",
        title: "tpwn: MIG io_service_open_extended type confusion + IOHDIXControllerUserClient __PAGEZERO OR-write",
        component: "IOKit MIG (io_service_open_extended) + IOHDIXControllerUserClient (Apple advisories said only 'IOKit')",
        kind: ComponentKind::IOKit,
        bug_class: "type confusion (mach-port) / arbitrary OR-write",
        affected: "iOS 9.0.x (fixed 9.1; patch batch CVE-2015-5932/5847/5864)",
        primitive: "mach-port type confusion via io_service_open_extended plus an OR-write landing in __PAGEZERO; a kalloc.1024 IOAudioEngineUserClient vtable leak defeats KASLR.",
        summary: "Todesco's tpwn chains two kernel bugs: MIG's io_service_open_extended accepts a mach-port type confusion that produces a controlled kernel object mismatch, and IOHDIXControllerUserClient exposes an OR-write that lands in __PAGEZERO, letting an attacker set bits in the otherwise unmapped zero page and stage fake vtables at low addresses. A heap groom in kalloc.1024 spraying IOAudioEngineUserClient objects leaks a vtable pointer, defeating KASLR. Apple's advisories bundled the fixes under generic 'IOKit' memory-corruption wording; the PoCs live at github.com/kpwn/tpwn.",
        techniques: &[
            "mach-port type confusion via MIG io_service_open_extended",
            "__PAGEZERO OR-write to stage fake vtables",
            "kalloc.1024 IOAudioEngineUserClient vtable spray/leak",
            "KASLR defeat",
            "patch-batch attribution: CVE-2015-5932/5847/5864",
        ],
        sources: &[
            "Luca Todesco, tpwn (github.com/kpwn/tpwn)",
            "Apple security advisory iOS 9.1 (CVE-2015-5932)",
        ],
        year: 2015,
    },
    // 10
    VulnEntry {
        id: "CVE-2015-6974",
        title: "npwn/Pangu9: IOHIDFamily UAF vtable vcall with SMAP-safe groom",
        component: "IOHIDFamily (kernel)",
        kind: ComponentKind::Kernel,
        bug_class: "UAF / refcount (vtable vcall)",
        affected: "iOS 9.0-9.0.2 / OS X 10.11 (fixed iOS 9.1 / OS X 10.11.1)",
        primitive: "use-after-free in IOHIDFamily surfaces as a virtual call through a freed object's vtable; the call is redirected straight to _csr_set_allow_all — a one-gadget, ROP-free SIP kill.",
        summary: "The npwn (OS X) and Pangu9 (iOS 9.0-9.0.2) exploits use an IOHIDFamily use-after-free that surfaces as a virtual call through a freed object's vtable. The heap groom runs in kalloc.256 and is SMAP-safe: on SMAP machines the fake object is built entirely in kernel zones rather than userspace, so the same layout works on both platforms. Rather than chaining ROP, the controlled vcall is redirected directly to _csr_set_allow_all, disabling SIP checks without a stack pivot. Reliability comes from a zalloc timing attack: mach_msg OOL vm_map_copyin operations are timed to predict when the freed element is recycled.",
        techniques: &[
            "IOHIDFamily UAF -> vtable vcall",
            "SMAP-safe kalloc.256 heap groom",
            "one-gadget redirect to _csr_set_allow_all (SIP bypass, no ROP)",
            "zalloc timing attack via mach_msg OOL vm_map_copyin",
        ],
        sources: &[
            "Pangu9 jailbreak (iOS 9.0-9.0.2)",
            "Apple security advisory iOS 9.1 (CVE-2015-6974)",
        ],
        year: 2015,
    },
    // 11
    VulnEntry {
        id: "CVE-2017-2456",
        title: "Mach VM OOL MOVE race: shared vm_object+offset ('the letter changes while reading')",
        component: "XNU Mach VM (vm_map_copyin/copyout OOL MOVE path)",
        kind: ComponentKind::Kernel,
        bug_class: "logic/race (OOL MOVE overlapping-region aliasing)",
        affected: "iOS 10.x era (research context; family revisited in PAC-era writeups)",
        primitive: "two threads MOVE overlapping VM regions so sender and receiver OOL memory alias at the same vm_object+offset; a flippable NULL byte then corrupts a consumer strcpy.",
        summary: "When a buffer carried in OOL descriptors is moved twice by racing threads, the MOVE path can leave two maps pointing at the same vm_object+offset, so a write made after delivery changes memory the receiver is concurrently parsing — 'the letter changes while you are reading it'. Ian Beer's OBTS v2 keynote frames this design-bug lineage, and the exploitation sketch passes the aliased buffer through an XPC OOL dictionary with a flippable NULL byte: flipping it mid-parse turns an in-bounds strcpy into an undersized one, overwriting an adjacent ObjC pointer. Brandon Azad's 'Splitting Atoms in XNU' extends the same Mach VM aliasing theme with an A12 PAC bypass via pacia context forgery, showing the family survived into the PAC era.",
        techniques: &[
            "racing vm_map_copyin/copyout OOL MOVE on overlapping regions",
            "shared vm_object+offset aliasing",
            "XPC OOL dictionary with flippable NULL byte",
            "undersized strcpy -> ObjC pointer overwrite",
            "A12 PAC bypass via pacia context forgery (Splitting Atoms in XNU)",
        ],
        sources: &[
            "Ian Beer, OBTS v2 keynote (XNU exploitation survey)",
            "Brandon Azad, 'Splitting Atoms in XNU' (Google Project Zero)",
            "Apple security advisory iOS 10.2.1 (CVE-2017-2456)",
        ],
        year: 2017,
    },
    // 12
    VulnEntry {
        id: "xpc-mig-design",
        title: "XPC/MIG design bugs: xpc_object_t void* type confusion and MIG subsystem discovery",
        component: "libxpc + userspace MIG servers (networkd, sysmond, fontd)",
        kind: ComponentKind::Daemon,
        bug_class: "type confusion (xpc_object_t) / unbounded decompression",
        affected: "no CVE (design-bug survey; live bugs at disclosure: networkd GS 130, sysmond GS 121)",
        primitive: "xpc_object_t is a void* whose type is checked only at use sites; cross-type confusion (+0x28/+0x30 uuid vs data) plus a 1GB xpc_dictionary_set_data spray yields daemon memory corruption.",
        summary: "Ian Beer's 2015 Japan Security Symposium material frames XPC and MIG as design bugs rather than single CVEs: xpc_object_t handles are untyped void*, so a receiver that confuses a UUID object for data reads past the +0x28/+0x30 fields into attacker-controlled memory, and xpc_dictionary_set_data with 1GB payloads sprays daemon heap to make reclamation deterministic. Live instances at disclosure time included networkd (Project Zero GS 130) and sysmond (GS 121); fontd's TCFResurrectContext decompresses attacker-supplied CFCharacterSet data without bounds checks. The same work documents recovering a daemon's MIG subsystem table and message IDs without symbols — the standard map for auditing any MIG service.",
        techniques: &[
            "xpc_object_t void* type confusion (+0x28/+0x30 uuid -> data)",
            "1GB xpc_dictionary_set_data heap spray",
            "networkd GS 130 / sysmond GS 121 live bugs",
            "fontd TCFResurrectContext unbounded CFCharacterSet decompression",
            "MIG subsystem discovery without symbols",
        ],
        sources: &[
            "Ian Beer, Japan Security Symposium 2015 (XPC/MIG attack surface)",
            "Google Project Zero issue tracker (GS 130 networkd, GS 121 sysmond)",
        ],
        year: 2015,
    },
    // 13
    VulnEntry {
        id: "CVE-2015-1140",
        title: "vpwn recap: kernel heap bugs patched as 'IOKit' (CVE-2015-1140 / CVE-2015-5865)",
        component: "XNU kernel heap (zalloc/kalloc); Apple advisories said only 'IOKit'",
        kind: ComponentKind::Kernel,
        bug_class: "UAF / freelist corruption (kernel heap)",
        affected: "fixed in the iOS 8.2 (CVE-2015-1140) and iOS 9 (CVE-2015-5865) batches",
        primitive: "OOL-port-driven kernel heap corruption refined across two fix cycles; the recap anchors the zone-allocator hardening timeline in this crate's mitigations().",
        summary: "Esser's HITB GSEC 2016 'iOS 10 Kernel Heap Pre-Survey' recaps the vpwn-era bugs: CVE-2015-1140 (fixed iOS 8.2) and CVE-2015-5865 (fixed iOS 9) both shipped in advisories under generic 'IOKit' memory-corruption wording, while the underlying issues were kernel heap (zalloc/kalloc) bugs reachable through mach_msg OOL descriptors. The recap matters less for the individual bugs than for the timeline it anchors: each Apple patch generation is one MitigationNote row in this crate, from the iOS 6 freelist cookies through the iOS 10 zone metadata relocation.",
        techniques: &[
            "mach_msg OOL port descriptors as the heap-shaping primitive",
            "kalloc zone grooming across fix cycles",
            "advisory-vs-component attribution (IOKit label vs XNU heap)",
            "zone allocator timeline: see mitigations()",
        ],
        sources: &[
            "Esser, HITB GSEC 2016 'iOS 10 Kernel Heap Pre-Survey'",
            "Apple security advisories iOS 8.2 / iOS 9 (CVE-2015-1140, CVE-2015-5865)",
        ],
        year: 2015,
    },
    // 14a
    VulnEntry {
        id: "learn-polyrop-cdpwn",
        title: "PolyROP/MultiROP: ASLR-blind ROP for one-directional broadcast protocols (CDPwn)",
        component: "research curriculum (no emulator component)",
        kind: ComponentKind::Learning,
        bug_class: "n/a (curriculum)",
        affected: "n/a (technique study; CDPwn case study: CVE-2020-3119/3111/3118)",
        primitive: "blind ROP without a response channel: gadgets selected so every intermediate state stays survivable on a one-way protocol such as CDP.",
        summary: "PolyROP and MultiROP address the hardest constraint in broadcast-protocol exploitation: the target never talks back, so no leak-and-respond ROP loop is possible. Gadgets are chosen so that every chained state is survivable regardless of the ASLR base, and multi-shot payload stages replace interactive feedback. CDPwn (Armis, RSAC 2020) is the case study: Cisco CDP parsing bugs CVE-2020-3119 (RCE), CVE-2020-3111 (memory leak) and CVE-2020-3118 (format string) exploited over a silent, switch-flooding channel. Directly relevant to the emulator's broadcast-style device interfaces (UART/HID) where no acknowledgement path exists.",
        techniques: &[
            "blind ROP gadget selection",
            "survivable intermediate states under ASLR",
            "multi-shot staging without feedback",
            "CDPwn CVE-2020-3119/3111/3118 case study",
        ],
        sources: &[
            "PolyROP/MultiROP blind-ROP research",
            "Armis, RSAC 2020 'CDPwn'",
        ],
        year: 2020,
    },
    // 14b
    VulnEntry {
        id: "learn-arm32-ret2libc-rop",
        title: "ARM32 ret2libc/ROP curriculum (Troopers18)",
        component: "research curriculum (no emulator component)",
        kind: ComponentKind::Learning,
        bug_class: "n/a (curriculum)",
        affected: "n/a",
        primitive: "graduated ARM32 exploit-development ladder: stack overflow -> ret2libc -> hand-built ROP.",
        summary: "The Troopers 2018 ARM curriculum walks the classic 32-bit ARM exploitation ladder on a deliberately vulnerable target: crash triage under GDB, finding the exact offset, ret2libc with symbol resolution, then hand-built ROP chains once NX closes the ret2libc door. Emphasis is on ARM calling conventions (r0-r3 arguments, LR on the stack), gadget hunting and thumb/ARM interworking. Good calibration for reading the emulator's AArch64 dispatch and for porting the same ladder into the A13's 64-bit world.",
        techniques: &[
            "ARM32 crash triage and offset discovery",
            "ret2libc with symbol resolution",
            "hand-built ROP chains",
            "thumb/ARM interworking and gadget hunting",
        ],
        sources: &[
            "Troopers 2018 ARM32 exploit-development curriculum",
        ],
        year: 2018,
    },
    // 14c
    VulnEntry {
        id: "learn-azeria-shellcode",
        title: "Azeria workshop: ARM shellcode and de-nullification",
        component: "research curriculum (no emulator component)",
        kind: ComponentKind::Learning,
        bug_class: "n/a (curriculum)",
        affected: "n/a",
        primitive: "write position-independent ARM shellcode with zero null bytes, then adapt it to filter-constrained sinks.",
        summary: "Azeria Labs' workshop material (from the ARM shellcode series) teaches hand-writing ARM syscall stubs, then de-nullifying them: re-encoding immediates, using offset arithmetic (sub/add) and branch tricks so no 0x00 byte survives — required when the sink is a C string or a protocol parser that truncates at NUL. Pairs with the ARM32 curriculum above and with the emulator's UART/HID byte-stream surfaces, where NUL bytes are exactly what gets eaten.",
        techniques: &[
            "hand-written ARM syscall stubs",
            "de-nullification: immediate re-encoding and offset ops",
            "string-truncation-safe payload staging",
        ],
        sources: &[
            "Azeria Labs ARM shellcode workshop (SAS)",
        ],
        year: 2017,
    },
    // 14d
    VulnEntry {
        id: "learn-mitigation-landscape",
        title: "Mitigation-landscape keynote case studies: SmartThings and Echo",
        component: "research curriculum (no emulator component)",
        kind: ComponentKind::Learning,
        bug_class: "n/a (curriculum)",
        affected: "n/a (case studies: CVE-2018-3863..3897, CVE-2018-3902..3925)",
        primitive: "n/a — uses published CVE batches as a lens on the ASLR/DEP-era mitigation landscape.",
        summary: "Keynote-style material mapping the modern mitigation landscape onto concrete CVE batches: Cisco Talos' SmartThings hub findings (CVE-2018-3863 through CVE-2018-3897 — stack overflows, command injection and heap issues across the hub's exposed services) and the Amazon Echo sequence (CVE-2018-3902 through CVE-2018-3925 — memory-corruption and same-origin issues reachable on the local network). The point of the keynote: mitigation posture, not any single bug, decides how far a class of issues carries. Useful framing when deciding which XNU-era hardenings the emulator should model.",
        techniques: &[
            "mitigation-landscape mapping",
            "CVE-batch triage: SmartThings CVE-2018-3863..3897",
            "CVE-batch triage: Echo CVE-2018-3902..3925",
        ],
        sources: &[
            "Cisco Talos SmartThings vulnerabilities (CVE-2018-3863..3897)",
            "Cisco Talos Amazon Echo vulnerabilities (CVE-2018-3902..3925)",
        ],
        year: 2018,
    },
    // 15
    VulnEntry {
        id: "xpc-data-shared-mem",
        title: "xpc_data backed by mach_make_memory_entry_64: sender-writable shared memory",
        component: "libxpc xpc_data / airportd (macOS PoC)",
        kind: ComponentKind::Daemon,
        bug_class: "design/shared-memory aliasing + double-fetch",
        affected: "no CVE (macOS research PoC)",
        primitive: "xpc_data whose backing store is sender-writable shared memory; the receiver's decodeCStringForKey: parses memory it does not own, and a size-then-parse double-fetch (__NSMS1) yields an OOB write.",
        summary: "Ian Beer's PoC replaces the usual OOL copy with an xpc_data backed by a mach_make_memory_entry_64 shared-memory entry, so the bytes the receiver parses remain writable by the sender after the send. airportd's decodeCStringForKey: reads a length, then parses the buffer — the __NSMS1 size-then-parse double-fetch lets the sender flip the NUL terminator between the two, turning an in-bounds parse into an OOB write. The design lesson encoded for the emulator: any IPC transport that does not copy-on-send inherits a double-fetch surface.",
        techniques: &[
            "mach_make_memory_entry_64-backed xpc_data",
            "sender-writable receiver-side memory",
            "__NSMS1 size-then-parse double-fetch",
            "OOB write via NUL flip after the size check",
            "airportd decodeCStringForKey: as the parsing target",
        ],
        sources: &[
            "Ian Beer (Google Project Zero) xpc_data shared-memory PoC",
        ],
        year: 2015,
    },
];

pub const MITIGATIONS: &[MitigationNote] = &[
    MitigationNote {
        era: "iOS 5 (2011-2012)",
        hardening: "kernel _MALLOC zone size-header overflow closed (the 'iOS Kernel Heap Armageddon' BH USA 2012 vector); kernel object storage consolidates in kalloc zones",
        defeated_by: "freelist injection via OOL/kalloc feng shui; OSObject vtable and retainCount overwrites untouched",
    },
    MitigationNote {
        era: "iOS 6 (2012-2013)",
        hardening: "zone freelist pointers XORed with per-zone cookies; freed elements poisoned with 0xdeadbeef",
        defeated_by: "cookie known-plaintext: free-then-realloc of a controlled object reveals the key, and freelist injection resumed",
    },
    MitigationNote {
        era: "iOS 7 (2013-2014)",
        hardening: "zone_page_metadata page lists: freelist reworked into per-page metadata pages joined by doubly-linked page lists",
        defeated_by: "the metadata pages themselves unprotected — corrupted page-list links had no validation (safe unlinking arrived only in iOS 8)",
    },
    MitigationNote {
        era: "iOS 8 (2014-2015)",
        hardening: "safe unlinking with neighbor validation plus zp_scale-scaled poisoning of freed elements",
        defeated_by: "vpwn-era OOL-port heap corruption (CVE-2015-1140) still found grooming room; poisoning checks run only on the free path",
    },
    MitigationNote {
        era: "iOS 9 (2015-2016)",
        hardening: "vm_map_copy element shrink (OOL sprays cost more), zone metadata relocated away from element memory, initial freelist randomized at zone expansion",
        defeated_by: "zalloc timing attacks via mach_msg OOL vm_map_copyin; groomable kalloc layouts persisted (npwn/Pangu9)",
    },
    MitigationNote {
        era: "iOS 10 (2016-2017)",
        hardening: "zone_metadata_region split + zone_array moved to __DATA:__bss, freelist pointer XORed with a per-zone nopoison cookie, wrong-zone-free panics",
        defeated_by: "exploitation cost raised sharply (Esser's 'pre-survey' verdict); heap feng shui survived via IOSurface/OSUnserializeXML sprays and the field pivoted toward IPC and logic bugs",
    },
];

pub const FRIDA_NOTES: &[FridaNote] = &[
    FridaNote {
        topic: "LD_PRELOAD to Frida porting",
        detail: "classic LD_PRELOAD shims map 1:1 to Interceptor.attach: onEnter reads/replaces args[i], onLeave rewrites retval — no recompilation, same symbol set",
    },
    FridaNote {
        topic: "r2frida :i/:ii/:iE/:ic",
        detail: "list module info/imports, symbols, exports and ObjC classes of the attached target without leaving the r2 prompt",
    },
    FridaNote {
        topic: "r2frida :dxo",
        detail: "invoke an ObjC method on a live object handle from r2 — quick runtime poking of private APIs",
    },
    FridaNote {
        topic: "r2frida :afs",
        detail: "recover/annotate function signatures at an address so the disassembly stays honest",
    },
    FridaNote {
        topic: "r2frida :dtf",
        detail: "formatted tracepoints: printf-style argument tracing at call sites with per-hit logging in the r2 session",
    },
    FridaNote {
        topic: "r2frida :dtr",
        detail: "register dumps at tracepoints — capture register state on each hit for argument/return studies",
    },
    FridaNote {
        topic: "r2frida remote FS",
        detail: "remote filesystem mounts over the session: /r2f/AppHome, /r2f/AppBundle and /r2f/Device give file access as the target",
    },
    FridaNote {
        topic: "Frida Gadget repack",
        detail: "inject Frida Gadget into a repacked IPA for non-jailbroken instrumentation: patch Mach-O load commands, re-sign, drive the gadget from its config file or TCP listener",
    },
    FridaNote {
        topic: "channels vs RPC",
        detail: "script.channels stream events continuously; rpc.exports is request/response — channels for tracing, RPC for structured tooling calls",
    },
    FridaNote {
        topic: "TypeScript agents",
        detail: "Frida agents in TypeScript (frida-compile toolchain): typed ObjC bridges and maintainable multi-module instrumentation",
    },
];

pub const TOOLS: &[ToolRef] = &[
    ToolRef {
        name: "MobSF",
        url: "https://github.com/MobSF/Mobile-Security-Framework-MobSF",
        what: "automated static and dynamic mobile app analysis (IPA scan, binary analysis, reporting)",
    },
    ToolRef {
        name: "objection",
        url: "https://github.com/sensepost/objection",
        what: "runtime mobile exploration toolkit built on Frida: hook, dump and instrument a running app",
    },
    ToolRef {
        name: "Needle",
        url: "https://github.com/FSecureLABS/needle",
        what: "module-based iOS security-testing framework (F-Secure/NCC, archived)",
    },
    ToolRef {
        name: "Keychain-Dumper",
        url: "https://github.com/ptoomey3/Keychain-Dumper",
        what: "dump keychain items on a jailbroken device (entitlement-driven keychain access)",
    },
    ToolRef {
        name: "PassionFruit",
        url: "https://github.com/chaitin/passionfruit",
        what: "web GUI for iOS dynamic analysis on top of Frida (archived)",
    },
    ToolRef {
        name: "iPhoneTunnel",
        url: "https://github.com/fontanell/iPhoneTunnel",
        what: "SSH-over-usbmuxd tunnel for device access without Wi-Fi",
    },
    ToolRef {
        name: "idb",
        url: "https://github.com/facebook/idb",
        what: "Facebook's iOS Development Bridge: device/app automation and testing hooks",
    },
    ToolRef {
        name: "iRET",
        url: "https://github.com/valkyrix/iRET",
        what: "iOS Reverse Engineering Toolkit: class dumping and plist/keychain inspection on device",
    },
    ToolRef {
        name: "ProvisionQL",
        url: "https://github.com/ealeksandrov/ProvisionQL",
        what: "QuickLook plugin rendering .ipa/.mobileprovision entitlements and profiles",
    },
    ToolRef {
        name: "obfuscator-llvm",
        url: "https://github.com/obfuscator-llvm/obfuscator",
        what: "LLVM-based control-flow flattening, bogus control flow and instruction substitution",
    },
    ToolRef {
        name: "Clutch",
        url: "https://github.com/KJCracks/Clutch",
        what: "decrypt App Store binaries on a jailbroken device (FairPlay offload)",
    },
    ToolRef {
        name: "Rasticrac",
        url: "https://github.com/KJCracks/Rasticrac",
        what: "alternative on-device binary decryption tool (dumpdecrypted lineage)",
    },
    ToolRef {
        name: "bfinject",
        url: "https://github.com/JohnCoates/bfinject",
        what: "inject dylibs/Frida into running apps on a jailbroken device",
    },
    ToolRef {
        name: "IPAPatch",
        url: "https://github.com/Chippppp/IPAPatch",
        what: "patch IPA bundles to embed FridaGadget (non-jailbreak instrumentation)",
    },
    ToolRef {
        name: "node-applesign",
        url: "https://github.com/nowsecure/node-applesign",
        what: "Node.js iOS codesigning/resigning library for IPA re-sign pipelines",
    },
    ToolRef {
        name: "iOS App Signer",
        url: "https://github.com/DanTheMan827/ios-app-signer",
        what: "GUI re-signer producing installable sideload builds from IPAs/debs",
    },
    ToolRef {
        name: "Cydia Impactor",
        url: "http://www.cydiaimpactor.com",
        what: "Saurik's IPA signing/sideloading utility (archived)",
    },
    ToolRef {
        name: "dumpdecrypted",
        url: "https://github.com/stefanesser/dumpdecrypted",
        what: "Stefan Esser's dylib that dumps the decrypted Mach-O from a running app",
    },
    ToolRef {
        name: "SSL Kill Switch 2",
        url: "https://github.com/nabla-c0d3/ssl-kill-switch2",
        what: "system-wide TLS pinning/certificate-validation kill switch for iOS",
    },
    ToolRef {
        name: "Theos",
        url: "https://github.com/theos/theos",
        what: "cross-platform iOS tweak/dev build system (logos hooks)",
    },
    ToolRef {
        name: "iOS-Runtime-Headers",
        url: "https://github.com/nst/iOS-Runtime-Headers",
        what: "dumped private framework headers across iOS versions",
    },
    ToolRef {
        name: "ipsw.me",
        url: "https://ipsw.me",
        what: "IPSW download index per device and signed version (kernelcache sourcing)",
    },
    ToolRef {
        name: "canijailbreak.com",
        url: "https://canijailbreak.com",
        what: "per-iOS-version jailbreak availability index",
    },
    ToolRef {
        name: "DVIA",
        url: "https://github.com/prateek147/DVIA-v2",
        what: "Damn Vulnerable iOS App v2 — practice target (swizzling, jailbreak detection, keychain)",
    },
    ToolRef {
        name: "iGoat",
        url: "https://github.com/OWASP/iGoat",
        what: "OWASP deliberate-vulnerability iOS app for secure-coding practice",
    },
    ToolRef {
        name: "iOS-CTF",
        url: "https://github.com/OWASP/ios-ctf",
        what: "OWASP iOS CTF challenges (crackmes, flag hunts) built on the iGoat tooling",
    },
    ToolRef {
        name: "darwin-xnu",
        url: "https://github.com/apple/darwin-xnu",
        what: "Apple's XNU kernel source mirror — the reference for heap/IPC emulation",
    },
    ToolRef {
        name: "ktrw",
        url: "https://github.com/googleprojectzero/ktrw",
        what: "Google Project Zero iPhone kernel debug/exploit workshop framework (KTRR era)",
    },
    ToolRef {
        name: "checkra.in",
        url: "https://checkra.in",
        what: "checkra1n jailbreak (checkm8 BootROM) home — boot-chain research context",
    },
    ToolRef {
        name: "kpwn/tpwn",
        url: "https://github.com/kpwn/tpwn",
        what: "Luca Todesco's iOS 9.1-era kernel PoCs (type confusion, vtable leak)",
    },
    ToolRef {
        name: "rani-i/bluetoothdPoC",
        url: "https://github.com/rani-i/bluetoothdPoC",
        what: "PoC for the bluetoothd MIG bugs (CVE-2018-4087/4095 family)",
    },
    ToolRef {
        name: "xerub/img4lib",
        url: "https://github.com/xerub/img4lib",
        what: "IMG4/IM4M/IM4P parsing and building library (boot-chain formats)",
    },
    ToolRef {
        name: "diaphora",
        url: "https://github.com/joxeankoret/diaphora",
        what: "binary diffing for patch analysis (kernelcache kernel-diff workflows)",
    },
    ToolRef {
        name: "blacktop/ipsw",
        url: "https://github.com/blacktop/ipsw",
        what: "Go CLI to parse and download IPSWs, kernelcaches and dyld shared caches",
    },
];
