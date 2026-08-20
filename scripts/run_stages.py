#!/usr/bin/env python3
"""What each layer of the circuit costs, by building the circuit one layer at a
time.

The round count of the whole circuit says how long a quote takes. It does not
say which part to attack, and the answer to that is not guessable from the
source: arithmetic over shares is free however wide it is, and a comparison is
expensive however narrow. The only way to attribute rounds to layers is to
compile the circuit with layers missing and read the difference.

Each cut opens one value that every layer above it feeds, so nothing already
built can be deleted as unused --- a deleted layer costs nothing, which would
make the attribution come out backwards. That reveal costs one round of its own
in each partial circuit, so it is the *increments* that attribute cost, and the
last increment is to the complete circuit, which has its own reveals instead.

What this measures is the compiler's count, not the runtime's. The two differ
--- the virtual machine opens values the compiler counts once --- and the
runtime count is the one the wall-clock figures follow. The compiler's is the
right unit here anyway: it is a property of the circuit, so it is the same on
every machine, and attributing a machine-independent cost to a layer is what
this is for.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from scripts.hosts import this_host                                  # noqa: E402

# In build order. The name is the layer the cut is *after*.
STAGES = [
    ("price", "inputs, reference lookup and price arithmetic"),
    ("direction", "+ direction selection"),
    ("gates", "+ eligibility gates"),
    ("tournament", "+ binary tournament"),
]


def compile_stage(root: Path, stage: str, extra: list[str]) -> dict:
    """One partial circuit, compiled and thrown away."""
    proc = subprocess.run(
        [sys.executable, str(HERE / "run_qomm.py"), "--prepare-only",
         "--mp-spdz-root", str(root), "--stop-after", stage, *extra],
        capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"stage {stage} did not compile:\n{proc.stderr[-3000:]}")
    payload = json.loads(proc.stdout)
    circuit = payload["circuit"]
    return {"stage": stage,
            "rounds": circuit["vm_rounds"],
            "opens": circuit["integer_opens"],
            "triples": circuit["integer_triples"],
            "bits": circuit["integer_bits"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mp-spdz-root", type=Path,
                    default=Path(os.environ.get("MP_SPDZ_ROOT", "")))
    ap.add_argument("--out", type=Path, default=Path("artifacts/stages.json"))
    ap.add_argument("--n-mm", type=int, default=16)
    ap.add_argument("--n-assets", type=int, default=4)
    ap.add_argument("--bit-length", type=int, default=31)
    args = ap.parse_args()

    common = ["--mode", "rfq", "--n-mm", str(args.n_mm), "--n-parties", "7",
              "--threshold", "2", "--disclose", "none",
              "--bit-length", str(args.bit_length), "--argmin-arity", "2",
              "--n-assets", str(args.n_assets), "--user-asset", "0",
              "--n-requests", "1", "--is-real", "1"]

    rows, previous = [], None
    for stage, description in STAGES:
        row = compile_stage(args.mp_spdz_root, stage, common)
        row["description"] = description
        row["increment"] = None if previous is None else row["rounds"] - previous
        previous = row["rounds"]
        rows.append(row)
        increment = "---" if row["increment"] is None else f"+{row['increment']}"
        print(f"  {description:44} {row['rounds']:4} rounds  {increment:>5}", flush=True)

    total = rows[-1]["rounds"]
    for row in rows:
        row["share_of_rounds"] = (None if row["increment"] is None
                                  else row["increment"] / total)

    payload = {"host": this_host(), "n_mm": args.n_mm, "n_assets": args.n_assets,
               "bit_length": args.bit_length, "counted_by": "compiler",
               "total_rounds": total, "stages": rows}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
