#!/usr/bin/env python3
"""Same-host control: run the existing 9-order CLOB fixture through the same harness.

Without this control, the QOMM numbers would be compared against a measurement
taken on different hardware (Apple Silicon / aarch64 container), which would
confound the circuit-structure effect with a hardware effect.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import statistics
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_qomm import MPSpdzRun  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mp-spdz-root", type=Path,
                    default=Path(os.environ.get("MP_SPDZ_ROOT", "")))
    ap.add_argument("--clob-dir", type=Path, required=True,
                    help="directory holding continuous_clob_7.mpc and inputs_7/")
    ap.add_argument("--delay-ms", type=float, default=0.0)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    root = args.mp_spdz_root.resolve()
    program = f"clob_baseline_{os.getpid()}"
    work = Path(tempfile.mkdtemp(prefix="clob-"))
    src = work / f"{program}.mpc"
    shutil.copy2(args.clob_dir / "continuous_clob_7.mpc", src)
    inputs = work / "inputs"
    inputs.mkdir()
    for party in range(7):
        shutil.copy2(args.clob_dir / "inputs_7" / f"Input-P{party}-0", inputs / f"Input-P{party}-0")

    run = MPSpdzRun(root, program, 7, 2)
    result = {
        "fixture": "continuous_clob_7 (9 orders, MAX_FILLS=4)",
        "delay_ms": args.delay_ms, "repeats": args.repeats,
        "host": socket.gethostname(), "n_parties": 7, "threshold": 2,
    }
    try:
        run.install(src, inputs)
        result["circuit"] = run.compile()
        result["circuit"].pop("compile_log", None)
        samples = []
        verified = True
        for _ in range(args.repeats):
            exec_result = run.execute(args.delay_ms)
            if not exec_result["ok"]:
                result["error"] = "party failure"
                result["log_tail"] = exec_result["log"][-3000:]
                verified = False
                break
            events = re.search(r"^MPC7_MATCH_EVENTS=(\d+)", exec_result["log"], re.M)
            volume = re.search(r"^MPC7_MATCH_VOLUME=(\d+)", exec_result["log"], re.M)
            got = (int(events.group(1)) if events else None,
                   int(volume.group(1)) if volume else None)
            verified = verified and got == (5, 7)
            result["verify_detail"] = f"got={got} want=(5, 7)"
            samples.append({
                "wall_seconds": exec_result["wall_seconds"],
                "party0_seconds": exec_result["party0_seconds"],
                "party0_mb": exec_result["party0_mb"],
                "party0_rounds": exec_result["party0_rounds"],
                "global_mb": exec_result["global_mb"],
            })
        result["samples"] = samples
        result["verified"] = verified
        if samples:
            result["wall_median"] = statistics.median(s["wall_seconds"] for s in samples)
            p0 = [s["party0_seconds"] for s in samples if s["party0_seconds"] is not None]
            result["party0_median"] = statistics.median(p0) if p0 else None
            result["measured_rounds"] = samples[0]["party0_rounds"]
            result["measured_mb"] = samples[0]["party0_mb"]
    finally:
        run.cleanup()
        shutil.rmtree(work, ignore_errors=True)

    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if result.get("verified") else 1


if __name__ == "__main__":
    raise SystemExit(main())
