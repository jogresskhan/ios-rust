#!/usr/bin/env python3
"""fetch_fixtures.py — download the real T8030 (iPhone 11) fixture set for
the ios-rust test suite, without pulling the whole 4.5 GB IPSW.

Uses HTTP Range requests against Apple's CDN to extract just:
  * kernelcache.release.iphone12b   (the T8030 A13 kernelcache, ~15 MB)
  * DeviceTree.n104ap.im4p          (the real ADT, ~210 KB)
  * BuildManifest.plist             (~420 KB)
plus a REAL TSS response (ApImg4Ticket) for the latest still-signed build
via the blacktop/ipsw CLI (`download tss` hits gs.apple.com for real).

Usage: fetch_fixtures.py <out_dir>
"""
import os
import subprocess
import sys
import tempfile
import urllib.request

IPSW_URL = (
    "https://updates.cdn-apple.com/2020SummerFCS/fullrestores/001-41790/"
    "9C47E642-C3EC-48F7-9DEF-97C1E3C77E83/"
    "iPhone11,8,iPhone12,1_13.7_17H35_Restore.ipsw"
)
IPSW_CLI = "https://github.com/blacktop/ipsw/releases/download/v3.1.634/ipsw_3.1.634_linux_x86_64.tar.gz"


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "fixtures"
    os.makedirs(out, exist_ok=True)
    here = os.path.dirname(os.path.abspath(__file__))

    # 1) partial-download the IPSW members via range requests
    print("== partial-downloading T8030 IPSW members (range requests) ==")
    r = subprocess.run(
        [sys.executable, os.path.join(here, "remote_zip_pull.py"), IPSW_URL, out,
         "kernelcache.release.iphone12b$", "DeviceTree.n104ap", "BuildManifest"],
        check=True,
    )

    # 2) real TSS response from Apple's signing server (only needs network;
    #    the T8030's own iOS 13 build is no longer signed, so capture the
    #    latest still-signed ticket — the IM4M structure is identical).
    print("== fetching a real TSS response from gs.apple.com ==")
    with tempfile.TemporaryDirectory() as td:
        ipsw_bin = os.path.join(td, "ipsw")
        subprocess.run(
            ["curl", "-sL", "--max-time", "300", "-o", ipsw_bin + ".gz", IPSW_CLI],
            check=True,
        )
        subprocess.run(["tar", "xzf", ipsw_bin + ".gz", "-C", td, "ipsw"], check=True)
        subprocess.run(
            [ipsw_bin, "download", "tss", "--device", "iPhone16,1", "--latest",
             "--ecid", "112233445566", "--output",
             os.path.join(out, "real-tss-A17Pro.im4m")],
            check=False,  # unsigned builds fail nonzero; artifact optional
        )
    have_tss = any(f.startswith("real-tss-") for f in os.listdir(out))
    print("TSS capture:", "yes" if have_tss else "not available (build unsigned)")

    # 3) keep only what the tests need (drop the XR cache / AOP fw if any)
    for f in list(os.listdir(out)):
        if f.startswith("kernelcache.release.iphone11b") or f.startswith("aopfw-"):
            os.remove(os.path.join(out, f))

    for f in sorted(os.listdir(out)):
        print(f"  {f}: {os.path.getsize(os.path.join(out, f)) // 1024} KB")
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
