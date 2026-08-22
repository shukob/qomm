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
                            build_per_party, check_width, coefficients,
                            field_bits_needed, mask_bits, opening_bits,
                            per_party_field_bits, verify, verify_per_party)


# stands in for the value the circuit opens once every input is in
BEACON = 0x9E3779B97F4A7C15


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


def measure_per_party(key, n_inputs: int, n_parties: int, repeats: int,
                      share_bits: int = 71) -> dict:
    """The same statement, opened once per party, so a failure has a name.

    `input_check` proves *an* input was substituted. This proves *which node*
    did it, which is the step from the first of the five rungs in
    `ACCOUNTABILITY.md` to the fourth. The commitments it combines are the ones
    `qomm_transport.roles.Dealing` already publishes, so what is measured here
    is the marginal cost and not the whole construction.
    """
    import secrets as _secrets
    shares = [[_secrets.randbelow(1 << share_bits) for _ in range(n_inputs)]
              for _ in range(n_parties)]
    blindings = [[key.random_blinding() for _ in range(n_inputs)]
                 for _ in range(n_parties)]
    context = b"qomm:per-party-check:bench"

    build_ms, verify_ms, named = [], [], None
    for _ in range(repeats):
        start = time.perf_counter()
        check = build_per_party(key, shares, blindings, context, BEACON)
        build_ms.append((time.perf_counter() - start) * 1e3)
        start = time.perf_counter()
        ok, _, culprits = verify_per_party(key, check, context, BEACON)
        verify_ms.append((time.perf_counter() - start) * 1e3)
        assert ok and not culprits
    # and that it names the right one, which is the only reason it exists
    check = build_per_party(key, shares, blindings, context, BEACON)
    from zk.input_check import PerPartyCheck, per_party_coefficients
    coeffs = per_party_coefficients(key, check.share_commitments,
                                    check.mask_commitments, context,
                                    BEACON)
    openings = list(check.openings)
    openings[3] += sum(coeffs)
    _, _, named = verify_per_party(
        key, PerPartyCheck(check.share_commitments, check.mask_commitments,
                           openings, check.opening_blindings,
                           check.challenge_bits), context, BEACON)
    return {"n_inputs": n_inputs, "n_parties": n_parties,
            "build_ms": summarise(build_ms), "verify_ms": summarise(verify_ms),
            "named_the_substituting_node": named == [3],
            "field_bits_needed": per_party_field_bits(n_inputs, 31)}


def measure(key, n_inputs: int, repeats: int) -> dict:
    values = [(-1) ** i * (37 * i + 5) for i in range(n_inputs)]
    blindings = [key.random_blinding() for _ in values]
    context = b"qomm:input-check:bench"

    build_ms, verify_ms = [], []
    accepted = True
    for _ in range(repeats):
        start = time.perf_counter()
        check = build(key, values, blindings, context, BEACON)
        build_ms.append((time.perf_counter() - start) * 1e3)
        start = time.perf_counter()
        ok, _ = verify(key, check, context, BEACON)
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
    ap.add_argument("--parties", type=int, default=7,
                    help="node count for the per-party arm, which names the "
                         "substituting node instead of only detecting it")
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
    pedersen = result["schemes"].get("pedersen")
    if pedersen is not None:
        from zk.commit import Pedersen as _P
        key = make_scheme("pedersen", group=args.group)
        rows = [measure_per_party(key, n, args.parties, max(3, args.repeats // 4))
                for n in args.inputs]
        aggregate = {r["n_inputs"]: r for r in pedersen["rows"]}
        for row in rows:
            base = aggregate.get(row["n_inputs"])
            if base:
                row["over_aggregate"] = {
                    "build": round(row["build_ms"]["median"]
                                   / base["build_ms"]["median"], 2),
                    "verify": round(row["verify_ms"]["median"]
                                    / base["verify_ms"]["median"], 2)}
        result["per_party"] = {
            "what": ("one opening per party instead of one over all inputs, so a "
                     "failing check names the node. The commitments it combines "
                     "are the ones roles.Dealing already publishes, so this is "
                     "the marginal cost."),
            "n_parties": exact(args.parties),
            "field_bits_needed": exact(per_party_field_bits(166, 31)),
            "aggregate_field_bits_needed": exact(field_bits_needed(166, 31)),
            "rows": rows}
        print("\nper-party (names the node) against aggregate (detects only):")
        for row in rows:
            over = row.get("over_aggregate", {})
            print(f"  {row['n_inputs']:>5} inputs  "
                  f"build {render(row['build_ms'], 2, ' ms'):>21}  "
                  f"verify {render(row['verify_ms'], 2, ' ms'):>21}  "
                  f"{over.get('verify', '?')}x  named={row['named_the_substituting_node']}")
        print(f"  field: {per_party_field_bits(166, 31)} bits against "
              f"{field_bits_needed(166, 31)} for the aggregate check")

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
