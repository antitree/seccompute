#!/usr/bin/env python3
"""Demo of combo finding visualization styles.

Run:
    python examples/viz_demo.py
"""

import sys
import os

# Allow running from repo root without install
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from seccompute.combos import ComboFinding
from seccompute.viz import render_combo_warning

# Sample combo findings for demonstration
DEMO_COMBOS = [
    ComboFinding(
        id="COMBO-io-uring-network-bypass",
        name="io_uring network bypass",
        description=(
            "io_uring_enter can submit IORING_OP_SOCKET, IORING_OP_CONNECT, "
            "IORING_OP_ACCEPT, IORING_OP_SEND, IORING_OP_RECV — performing "
            "full network I/O without invoking the blocked socket/connect/send/recv "
            "syscalls directly. seccomp sees only io_uring_enter, not the "
            "underlying network operation."
        ),
        triggered_by=["io_uring_setup", "io_uring_enter"],
        bypasses_blocked=["socket", "connect", "bind", "accept", "sendto", "recvfrom"],
        severity="HIGH",
        references=["TECHNIQUE-io-uring-escape", "CVE-2023-2598", "CVE-2024-0582"],
    ),
    ComboFinding(
        id="COMBO-io-uring-file-io-bypass",
        name="io_uring file I/O bypass",
        description=(
            "io_uring_enter can submit IORING_OP_READ, IORING_OP_WRITE, "
            "IORING_OP_FSYNC, IORING_OP_FALLOCATE, IORING_OP_FADVISE — "
            "performing file I/O and memory operations without invoking "
            "the corresponding syscalls directly."
        ),
        triggered_by=["io_uring_setup", "io_uring_enter"],
        bypasses_blocked=["read", "write", "pread64", "pwrite64", "fsync", "fallocate", "fadvise64", "madvise"],
        severity="MEDIUM",
        references=["TECHNIQUE-io-uring-escape"],
    ),
]


def main() -> None:
    for style in (1, 2, 3, 4):
        style_names = {1: "Attack Chain", 2: "Hacker Terminal", 3: "Security Report", 4: "Merged"}
        print(f"\n{'=' * 72}")
        print(f"  STYLE {style}: {style_names[style]}")
        print(f"{'=' * 72}")
        for combo in DEMO_COMBOS:
            print(render_combo_warning(combo, style=style))


if __name__ == "__main__":
    main()
