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
from zk.scheme import make_scheme                                    # noqa: E402
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


def calibrate(scheme, n: int = 200) -> dict:
    """One `scale`, so the rest can be read as a count of them.

    On Pedersen that is a scalar multiplication; on VOLE it is two field
    multiplications. Calibrating on the operation rather than on the curve is
    what makes the two schemes comparable at all.
    """
    commitment = scheme.commit(12345, scheme.random_blinding())
    scalar = scheme.random_scalar()
    seconds = []
    for _ in range(n):
        start = time.perf_counter()
        scheme.scale(commitment, scalar)
        seconds.append(time.perf_counter() - start)
    return summarise([s * 1e6 for s in seconds])


def measure(key, n_inputs: int, repeats: int) -> dict:
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

    point = len(key.encode(key.commit(1, 1)))
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
    ap.add_argument("--schemes", nargs="+", default=["pedersen", "vole"],
                    help="commitment schemes to measure, from zk/scheme.py")
    ap.add_argument("--inputs", type=int, nargs="+", default=[16, 64, 166, 512])
    ap.add_argument("--repeats", type=int, default=20)
    args = ap.parse_args()

    result = {"host": this_host(), "group": args.group, "repeats": args.repeats,
              "challenge_bits": CHALLENGE_BITS,
              "width_budget": width_budget(),
              "schemes": {}}
    for name in args.schemes:
        scheme = make_scheme(name, **({"group": args.group} if name == "pedersen" else {}))
        unit = calibrate(scheme)
        block = {"publicly_verifiable": scheme.publicly_verifiable,
                 "scale_us": unit, "rows": []}
        print(f"== {name} == one scale: {unit['median']:.3f} us   "
              f"publicly verifiable: {scheme.publicly_verifiable}")
        for n in args.inputs:
            row = measure(scheme, n, args.repeats)
            block["rows"].append(row)
            print(f"  {n:>5} inputs  build {render(row['build_ms'], 2, ' ms'):>21}  "
                  f"verify {render(row['verify_ms'], 2, ' ms'):>21}  "
                  f"accepted={row['accepted']}")
        result["schemes"][name] = block
        print()
    ped = result["schemes"].get("pedersen"); vol = result["schemes"].get("vole")
    if ped and vol:
        result["vole_speedup"] = {
            "scale": round(ped["scale_us"]["median"] / vol["scale_us"]["median"], 1),
            "verify_at_166": round(ped["rows"][2]["verify_ms"]["median"]
                                   / vol["rows"][2]["verify_ms"]["median"], 1)
            if len(ped["rows"]) > 2 else None}
        print(f"VOLE is {result['vole_speedup']['scale']}x on one scale and "
              f"{result['vole_speedup']['verify_at_166']}x on verify at 166 inputs")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"\nwrote {args.out}")
    return 0 if all(r["accepted"] for b in result["schemes"].values()
                    for r in b["rows"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
