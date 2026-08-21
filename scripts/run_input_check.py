#!/usr/bin/env python3
"""What the input check costs, against what it is an alternative to.

`policy_audit` proves the shares open to the committed policy and says it does
not reach the shares MP-SPDZ consumes. Two ways to close that: run the
computation over the commitment field, which `matched_field.json` prices at 2.0
to 2.5 times the clock and seven to fourteen times the traffic on every quote;
or check the inputs with one random linear combination, which is this.

Three numbers, because they are paid by different people. The dealer builds it
once per dealing. Anyone verifies it. And the circuit carries one extra opening,
which is the part that shows up in the quote.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.hosts import this_host                                  # noqa: E402
from scripts.measure import exact, render, summarise                 # noqa: E402
from zk.commit import Pedersen                                       # noqa: E402
from zk.groups import make_group                                     # noqa: E402
from zk.input_check import (CHALLENGE_BITS, WidthError, build,       # noqa: E402
                            check_width, coefficients, field_bits_needed,
                            mask_bits, opening_bits, verify)


def width_budget() -> dict:
    """What the check needs from the field, which is the finding rather than a note.

    The opening fits a 127-bit prime with seven bits to spare. The mask does
    not: it is 119 of those 120 bits and it is an input like any other, so it is
    dealt with forty bits of slack per share, and seven shares of it need 164.
    """
    out = {"n_inputs": 166, "value_bits": 31, "challenge_bits": CHALLENGE_BITS,
           "opening_bits": opening_bits(166, 31),
           "mask_bits": mask_bits(166, 31),
           "field_bits_needed": field_bits_needed(166, 31),
           "group_order_bits": 252}
    for label, prime_bits in (("mp_spdz_default_128", 127),
                              ("wide_enough", 192),
                              ("group_order", 252)):
        try:
            check_width(166, 31, prime_bits, 252)
            out[label] = "fits"
        except WidthError as refused:
            out[label] = f"refused: {refused}"
    out["finding"] = (
        "The check does not run in the field it was proposed to save. It needs "
        "about 164 bits against 253 for the group order, and at 253 the same "
        "widening also makes threshold_sigma assemble correctly --- so the "
        "question is whether 164 is worth it over 253, not whether the check "
        "avoids widening at all.")
    return out


def calibrate(key: Pedersen, n: int = 200) -> dict:
    """One scalar multiplication, so the rest can be read as a count of them."""
    point, scalar = key.h, key.group.random_scalar()
    seconds = []
    for _ in range(n):
        start = time.perf_counter()
        key.group.point_pow(point, scalar)
        seconds.append(time.perf_counter() - start)
    return summarise([s * 1e6 for s in seconds])


def measure(key: Pedersen, n_inputs: int, repeats: int) -> dict:
    values = [(-1) ** i * (37 * i + 5) for i in range(n_inputs)]
    blindings = [key.random_blinding() for _ in values]
    context = b"qomm:input-check:bench"

    build_ms, verify_ms = [], []
    accepted = True
    for _ in range(repeats):
        start = time.perf_counter()
        check = build(key, values, blindings, context)
        build_ms.append((time.perf_counter() - start) * 1e3)
        start = time.perf_counter()
        ok, _ = verify(key, check, context)
        verify_ms.append((time.perf_counter() - start) * 1e3)
        accepted = accepted and ok

    point = len(key.group.encode(key.h))
    scalar = 32
    return {
        "n_inputs": n_inputs,
        "build_ms": summarise(build_ms),
        "verify_ms": summarise(verify_ms),
        "accepted": accepted,
        # the per-input commitments are already published by `deal_committed`,
        # so what this check adds is the mask commitment and the opening
        "published_bytes_incremental": exact(point + scalar + scalar),
        "published_bytes_standalone": exact((n_inputs + 1) * point + 2 * scalar),
        "opening_bits": exact(opening_bits(n_inputs, 31)),
        "soundness_bits": exact(CHALLENGE_BITS),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ROOT / "artifacts" / "input_check.json")
    ap.add_argument("--group", default="ed25519")
    ap.add_argument("--inputs", type=int, nargs="+", default=[16, 64, 166, 512])
    ap.add_argument("--repeats", type=int, default=20)
    args = ap.parse_args()

    key = Pedersen(make_group(args.group), b"qomm:input-check:v1")
    result = {"host": this_host(), "group": args.group, "repeats": args.repeats,
              "challenge_bits": CHALLENGE_BITS,
              "scalar_mult_us": calibrate(key),
              "width_budget": width_budget(),
              "rows": []}
    unit = result["scalar_mult_us"]["median"]
    print(f"scalar multiplication: {unit:.1f} us\n")
    for n in args.inputs:
        row = measure(key, n, args.repeats)
        result["rows"].append(row)
        print(f"{n:>5} inputs  build {render(row['build_ms'], 2, ' ms'):>22}  "
              f"verify {render(row['verify_ms'], 2, ' ms'):>22}  "
              f"= {1e3 * row['verify_ms']['median'] / unit:5.0f} scalar mults  "
              f"accepted={row['accepted']}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"\nwrote {args.out}")
    return 0 if all(r["accepted"] for r in result["rows"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
