#!/usr/bin/env python3
"""Does the protocol keep going when a party lies, or does it still stop?

`decode_patch.json` made the engine name the party that sent a wrong share. It
still stopped: naming is rung 4 and not rung 5, and `ACCOUNTABILITY.md` says so.
This is the run that tells the two apart, and the difference is not a number ---
it is whether the answer comes out.

The construction under test, `patches/robust-atlas.patch`:

  * `n >= 4T + 1`, because a product before degree reduction is a degree-`2T`
    codeword and Reed--Solomon corrects `e` errors iff `n - d >= 2e + 1`. At
    `n = 7, T = 2` the capacity is 1 and one short; at `n = 9` it is exactly 2.
  * ATLAS sends the masked product to a rotating **king**, which interpolates
    from `2T+1` shares and re-shares at degree `T`. That is where "consistent
    but wrong" lives: a lying king re-shares a perfectly consistent sharing of
    the wrong value and nothing catches it.
  * The masked product is **not secret** --- the mask is a fresh degree-`2T`
    random --- so it goes to everybody instead, and every party decodes it with
    Berlekamp--Welch for itself. No king, no segments, no player elimination.

`QOMM_CORRUPT_PLAYER` makes the listed parties send a wrong share of every
masked product. One environment variable read by all parties, so a single value
corrupts exactly the ones named.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.hosts import this_host                                  # noqa: E402
from scripts.run_qomm import MPSpdzRun                               # noqa: E402

PROGRAM = """
a = sint.get_input_from(0)
b = sint.get_input_from(1)
x = a.expand_to_vector({n_mults})
y = b.expand_to_vector({n_mults})
arr = sint.Array({n_mults})
arr.assign(x * y)
print_ln('QOMM_RESULT=%s', arr.sum().reveal())
"""

RESULT = re.compile(r"QOMM_RESULT=(-?\d+)")
NAMED = re.compile(r"ROBUST_ATLAS_CORRECTED player (\d+)")
REFUSED = re.compile(r"(robust ATLAS needs n >= 4t\+1[^\n]*)")
CAPACITY = re.compile(r"(more than \d+ parties sent wrong shares[^\n]*)")


def one_run(root: Path, n_parties: int, threshold: int, n_mults: int,
            corrupt: list[int], tag: str, robust: bool = True) -> dict:
    run = MPSpdzRun(root, f"robust{tag}", n_parties, threshold,
                    binary="atlas-party.x")
    if robust:
        run.extra_args += ["--options", "robust"]
    source = run.run_dir / "prog.mpc"
    source.write_text(PROGRAM.format(n_mults=n_mults), encoding="utf-8")
    inputs = run.run_dir / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    for p in range(n_parties):
        (inputs / f"Input-P{p}-0").write_text("7\n", encoding="utf-8")
    run.install(source, inputs)
    run.compile()

    # every party reads the same variable and only the listed ones act on it,
    # so one value in the shared environment corrupts exactly those parties
    before = os.environ.get("QOMM_CORRUPT_PLAYER")
    os.environ["QOMM_CORRUPT_PLAYER"] = ",".join(str(c) for c in corrupt)
    try:
        out = run.execute(delay_ms=0.0)
    finally:
        if before is None:
            os.environ.pop("QOMM_CORRUPT_PLAYER", None)
        else:
            os.environ["QOMM_CORRUPT_PLAYER"] = before

    log = out["log"]
    results = sorted(set(int(m) for m in RESULT.findall(log)))
    named = sorted(set(int(m) for m in NAMED.findall(log)))
    refusal = REFUSED.search(log)
    capacity = CAPACITY.search(log)
    expected = 49 * n_mults
    return {
        "corrupted": corrupt,
        "finished": bool(out["ok"]),
        "answer": results[0] if len(results) == 1 else results,
        "expected": expected,
        "answer_correct": results == [expected],
        "named": named,
        "named_exactly_the_corrupted": named == sorted(corrupt),
        "refused_to_start": refusal.group(1) if refusal else None,
        "refused_past_capacity": capacity.group(1) if capacity else None,
        "rounds": out["party0_rounds"],
        "global_mb": out["global_mb"],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--parties", type=int, default=9)
    ap.add_argument("--threshold", type=int, default=2)
    ap.add_argument("--mults", type=int, default=2000)
    ap.add_argument("--out", type=Path,
                    default=ROOT / "artifacts" / "robust_atlas.json")
    args = ap.parse_args()

    n, t, m = args.parties, args.threshold, args.mults
    capacity = (n - 2 * t - 1) // 2
    arms = {}

    arms["king_honest"] = one_run(args.root, n, t, m, [], "kh", robust=False)
    arms["honest"] = one_run(args.root, n, t, m, [], "h")
    for k in range(1, capacity + 2):          # one past capacity on purpose
        who = list(range(k))
        arms[f"corrupt_{k}"] = one_run(args.root, n, t, m, who, f"c{k}")
    arms["corrupt_last_party"] = one_run(args.root, n, t, m, [n - 1], "cl")
    arms["too_few_parties"] = one_run(args.root, 7, t, m, [], "few")

    out = {
        "host": this_host(),
        "question": ("Naming was rung 4 because the protocol still stopped. "
                     "Does dropping the king and decoding at every party reach "
                     "rung 5 --- the answer comes out anyway?"),
        "setting": {"n_parties": n, "threshold": t, "multiplications": m,
                    "decoding_capacity_on_a_degree_2t_product": capacity,
                    "n_over_4t_plus_1": f"{n} >= {4 * t + 1}"},
        "arms": arms,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=1), encoding="utf-8")

    for name, a in arms.items():
        flag = "OK " if a["finished"] and a["answer_correct"] else "STOP"
        print(f"{flag} {name:22} answer={a['answer']} "
              f"named={a['named']} rounds={a['rounds']}")
        for key in ("refused_to_start", "refused_past_capacity"):
            if a[key]:
                print(f"       {key}: {a[key]}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
