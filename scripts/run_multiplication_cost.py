#!/usr/bin/env python3
"""What one multiplication costs here, so the robustness question has a number.

Goyal, Song and Zhu (CRYPTO 2020) title their paper *Guaranteed Output Delivery
Comes Free in Honest Majority MPC*, and give the price of that freedom as **5.5
field elements per party per multiplication in the best case and 7.5 once a
corrupted party has been identified**, against 5.5 for the best semi-honest
protocol at `t < n/2`. Their setting includes this deployment: seven nodes,
`T = 2`.

"Free" is a claim about a baseline, and the baseline that matters here is not
theirs --- it is `malicious-shamir-party.x`, which is what this stack actually
runs and which is secure **with abort**: MP-SPDZ's own README says "malicious
means that not following the protocol will at least be detected". Nobody is
named and the protocol stops.

So the question is arithmetic once one number is known: **how many field
elements per party does the engine we run spend on a multiplication?** If it is
near 5.5, guaranteed output delivery is genuinely free here and the only thing
missing is an implementation. If it is far below, "free" is a statement about a
protocol we are not running and robustness would be a real bill.

The measurement is a slope, not a ratio of totals: two circuit sizes, and the
per-multiplication cost is the difference divided by the difference. A single
size would fold in the setup, the input reads and the output opening, and at
small circuit sizes those dominate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.hosts import this_host                                  # noqa: E402
from scripts.measure import exact, summarise                         # noqa: E402
from scripts.run_qomm import MPSpdzRun                               # noqa: E402

PROGRAM = """
# {n_mults} multiplications in ONE SIMD row, so the round count stays at three
# and only traffic moves with the size. The first version of this ran a
# sequential `for_range` and measured 22,002 rounds for 22,000 multiplications
# --- a multiplication on the critical path, which is a different and much more
# expensive thing than a multiplication. The quote circuit batches; so does this.
a = sint.get_input_from(0)
b = sint.get_input_from(1)
x = a.expand_to_vector({n_mults})
y = b.expand_to_vector({n_mults})
arr = sint.Array({n_mults})
arr.assign(x * y)
print_ln('%s', arr.sum().reveal())
"""

# The same shape with the multiplications removed, so their cost can be
# separated from the input sharing, the single opening and the setup. The slope
# between two sizes of this is what does NOT belong to a multiplication.
CONTROL = """
a = sint.get_input_from(0)
b = sint.get_input_from(1)
x = a.expand_to_vector({n_mults})
arr = sint.Array({n_mults})
arr.assign(x + b.expand_to_vector({n_mults}))
print_ln('%s', arr.sum().reveal())
"""


def write_inputs(directory: Path, n_parties: int) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for p in range(n_parties):
        (directory / f"Input-P{p}-0").write_text("7\n", encoding="utf-8")


def one_size(root: Path, n_mults: int, n_parties: int, threshold: int,
             field_bits: int, repeats: int, binary: str, template: str,
             tag: str, file_prep: bool = False,
             prime: int | None = None) -> dict:
    run = MPSpdzRun(root, f"multcost{tag}{n_mults}", n_parties, threshold,
                    binary=binary)
    if file_prep:
        # -F on the party binary consumes preprocessing from files, so the
        # measurement is the online phase only. Without it a single-phase run
        # folds triple generation into the per-multiplication cost, which is the
        # comparison GSZ's single-phase protocol wants but not the one a
        # deployment with an offline phase would pay.
        run.extra_args += ["-F"]
        if prime:
            # the preprocessing on disk was generated for one modulus and the
            # binary defaults to a 256-bit representation, so it has to be told
            run.extra_args += ["-P", str(prime)]
    source = run.run_dir / "prog.mpc"
    source.write_text(template.format(n_mults=n_mults), encoding="utf-8")
    inputs = run.run_dir / "inputs"
    write_inputs(inputs, n_parties)
    run.install(source, inputs)
    compiled = run.compile()
    samples = [run.execute(delay_ms=0.0) for _ in range(repeats)]
    return {
        "n_mults": exact(n_mults),
        "field_bits": exact(field_bits),
        "compile_rounds": compiled.get("vm_rounds"),
        "global_mb": summarise([s["global_mb"] for s in samples]),
        "party0_rounds": exact(samples[0]["party0_rounds"]),
    }


def slope(rows: list[dict], n_parties: int, field_bits: int,
          delta_mults: int) -> dict:
    delta_mb = rows[1]["global_mb"]["median"] - rows[0]["global_mb"]["median"]
    global_bytes = delta_mb * 1e6 / delta_mults
    per_party = global_bytes / n_parties
    return {"global_bytes": round(global_bytes, 2),
            "per_party_bytes": round(per_party, 2),
            "per_party_elements": round(per_party / (field_bits / 8), 3)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, required=True, help="MP-SPDZ checkout")
    ap.add_argument("--parties", type=int, default=7)
    ap.add_argument("--threshold", type=int, default=2)
    ap.add_argument("--sizes", type=int, nargs=2, default=[2000, 22000],
                    help="two circuit sizes; the slope between them is the answer")
    ap.add_argument("--field-bits", type=int, default=128)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--prime", type=int, default=None,
                    help="the modulus the preprocessing on disk was made for; "
                         "read it from Player-Data/<n>-MSpT<t>-<bits>/Params-Data")
    ap.add_argument("--file-prep", action="store_true",
                    help="consume preprocessing from files, so the figure is the "
                         "online phase only")
    ap.add_argument("--control", action="store_true",
                    help="also run the multiplication-free control and the "
                         "semi-honest arm, which is what validates the instrument")
    ap.add_argument("--out", type=Path,
                    default=ROOT / "artifacts" / "multiplication_cost.json")
    args = ap.parse_args()

    small, large = sorted(args.sizes)
    delta = large - small
    element_bytes = args.field_bits / 8

    arms = {}
    for name, binary in (("malicious", "malicious-shamir-party.x"),
                         ("semi_honest", "shamir-party.x")):
        if name == "semi_honest" and not args.control:
            continue
        rows = [one_size(args.root, n, args.parties, args.threshold,
                         args.field_bits, args.repeats, binary, PROGRAM,
                         name[:3], args.file_prep, args.prime)
                for n in (small, large)]
        arm = {"binary": binary, "rows": rows,
               "per_multiplication": slope(rows, args.parties, args.field_bits, delta)}
        if args.control:
            control = [one_size(args.root, n, args.parties, args.threshold,
                                args.field_bits, args.repeats, binary, CONTROL,
                                name[:3] + "c", args.file_prep, args.prime)
                       for n in (small, large)]
            overhead = slope(control, args.parties, args.field_bits, delta)
            arm["control_no_multiplications"] = {"rows": control, "slope": overhead}
            arm["per_multiplication_net"] = {
                "per_party_elements": round(
                    arm["per_multiplication"]["per_party_elements"]
                    - overhead["per_party_elements"], 3)}
        arms[name] = arm

    result = {
        "host": this_host(),
        "n_parties": exact(args.parties),
        "threshold": exact(args.threshold),
        "field_bits": exact(args.field_bits),
        "security_of_the_baseline": (
            "with abort. MP-SPDZ's README: 'malicious means that not following "
            "the protocol will at least be detected'. No party is named and the "
            "protocol stops."),
        "arms": arms,
        "file_prep": exact(args.file_prep),
        "comparison": {
            "gsz2020_god_best_case_elements_per_party": 5.5,
            "gsz2020_god_after_identification": 7.5,
            "gsz2020_best_semi_honest": 5.5,
            "gsz2020_threshold": ("t < n/2 assuming broadcast; at t < n/3 the "
                                  "broadcast channel can be simulated over "
                                  "point-to-point links"),
            "this_deployment": ("n=7, T=2, which is t < n/3 (2 < 2.33), so no "
                                "broadcast channel has to be assumed"),
        },
    }
    mal = arms["malicious"]
    here = mal.get("per_multiplication_net", mal["per_multiplication"])["per_party_elements"]
    result["comparison"]["measured_here"] = here
    result["comparison"]["god_over_this_baseline"] = (
        round(5.5 / here, 2) if here else None)
    result["reading"] = (
        "A ratio near or below 1 means guaranteed output delivery costs about "
        "what this engine already spends, so 'comes free' holds against the "
        "baseline actually deployed and the gap is an implementation. Well above "
        "1 means 'free' was said about a protocol we are not running.")

    for name, arm in arms.items():
        net = arm.get("per_multiplication_net")
        print(f"{name:>12}: {arm['per_multiplication']['per_party_elements']:7.3f} "
              f"elements/party gross"
              + (f", {net['per_party_elements']:7.3f} net of the control" if net else ""))
        print(f"              rounds {[r['party0_rounds']['exact'] for r in arm['rows']]}"
              f" for {[r['n_mults']['exact'] for r in arm['rows']]} multiplications")
    print(f"\nGSZ 2020 guaranteed output delivery: 5.5 to 7.5 elements per party")
    print(f"ratio: {result['comparison']['god_over_this_baseline']}x")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
