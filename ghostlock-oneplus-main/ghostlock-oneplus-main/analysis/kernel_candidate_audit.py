#!/usr/bin/env python3
"""Offline, non-invasive kernel candidate audit.

This tool only reads a kernel source tree and an optional .config file.  It
does not talk to a device, execute a PoC, mutate images, or attempt privilege
escalation.  It records whether source/configuration markers associated with
selected Android kernel issues are present.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def window(text: str, needle: str, radius: int = 6000) -> str:
    pos = text.find(needle)
    if pos < 0:
        return ""
    return text[max(0, pos - radius) : pos + radius]


def check_posix_cpu_timer_fix(tree: Path, config: str) -> dict[str, Any]:
    path = tree / "kernel" / "time" / "posix-cpu-timers.c"
    text = read_text(path) if path.is_file() else ""
    run = window(text, "void run_posix_cpu_timers")
    has_guard = "if (tsk->exit_state)" in run
    task_work_enabled = "CONFIG_POSIX_CPU_TIMERS_TASK_WORK=y" in config
    return {
        "source": str(path),
        "source_found": path.is_file(),
        "exit_state_guard_present": has_guard,
        "task_work_config_enabled": task_work_enabled,
        "assessment": (
            "fixed-marker-present"
            if has_guard or task_work_enabled
            else "candidate-needs-exact-image-verification"
        ),
    }


def check_binder_fix(tree: Path) -> dict[str, Any]:
    path = tree / "drivers" / "android" / "binder.c"
    text = read_text(path) if path.is_file() else ""
    # The transaction routine is large and the object-copy loop can be far
    # beyond the function's declaration.  These markers are intentionally
    # checked across the file, then reviewed manually before any conclusion.
    txn = text
    markers = {
        "copy_size_marker": "copy_size = object_offset - user_offset" in txn,
        "user_copy_marker": "binder_alloc_copy_user_to_buffer" in txn,
        "object_validation_marker": "object_offset > tr->data_size" in txn,
    }
    return {
        "source": str(path),
        "source_found": path.is_file(),
        "markers": markers,
        "assessment": (
            "post-fix-shaped-binder-flow"
            if all(markers.values())
            else "requires-manual-review"
        ),
    }


def check_hkip(config: str) -> dict[str, Any]:
    names = (
        "CONFIG_HHEE",
        "CONFIG_HKIP_PRMEM",
        "CONFIG_HKIP_MAP_KERNEL_PROTECT",
        "CONFIG_HKIP_SELINUX_PROT",
        "CONFIG_HKIP_XOM_CODE",
        "CONFIG_HKIP_PRMEM_BYPASS",
        "CONFIG_HKIP_PROTECT_CRED",
        "CONFIG_HHEE_DEBUG",
    )
    values = {}
    for name in names:
        if f"{name}=y" in config:
            values[name] = "y"
        elif f"{name}=m" in config:
            values[name] = "m"
        elif f"# {name} is not set" in config:
            values[name] = "n"
        else:
            values[name] = "unknown"
    return {"config": values}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-tree", type=Path, required=True)
    parser.add_argument("--config", type=Path)
    parser.add_argument(
        "--config-stdin",
        action="store_true",
        help="read a kernel .config from stdin without creating a local file",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.config_stdin:
        config = sys.stdin.read()
    else:
        config = read_text(args.config) if args.config and args.config.is_file() else ""
    result = {
        "mode": "offline-read-only",
        "kernel_tree": str(args.kernel_tree),
        "cve_2025_38352": check_posix_cpu_timer_fix(args.kernel_tree, config),
        "cve_2023_20938": check_binder_fix(args.kernel_tree),
        "hkip_hhee": check_hkip(config),
    }
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
