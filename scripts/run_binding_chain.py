#!/usr/bin/env python3
"""The whole chain, run: committed, in band, shared, checked, computed, verified.

`BINDING.md` said what closing this needs and measured what the field costs.
This runs it. One market goes through `zk/binding.py` --- every input committed,
range-proved and Shamir-shared in the same pass that writes the party files ---
and then through MP-SPDZ over the field those shares are elements of, and the
answer is checked against the cleartext reference.

Three arms, because a chain that only ever succeeds says nothing:

    honest       every link holds and the circuit answers correctly
    bad dealer   the maker commits to one policy and deals another. Caught by
                 the node's own share check, before anything is computed.
    substituted  a node feeds a share other than the one it was dealt. **Not**
                 caught here, and the run says so rather than implying
                 otherwise: that is `zk/input_check.py`'s job, and the two
                 catch different parties.

Needs a built MP-SPDZ. Without one it still runs everything except the circuit
and says which part it skipped.
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "mp_spdz"))

from gen_qomm import (ED25519_ORDER, FIELDS, build_inputs,  # noqa: E402
                      build_program, finish_reference)
from scripts.hosts import this_host                                      # noqa: E402
from scripts.run_qomm import MPSpdzRun, verify                           # noqa: E402
from qomm_transport.binding import (BindingDealer, check_all, check_range,            # noqa: E402
                        check_share, reconstruct)
from zk.groups import make_group                                         # noqa: E402
from zk.policy_audit import PolicyBounds                                 # noqa: E402
from qomm_transport.roles import lagrange_at_zero                        # noqa: E402


def deal_market(group, n_mm, n_parties, threshold, seed, market):
    """One market, committed and shared in the pass that writes the party files."""
    dealer = BindingDealer(group, n_parties, threshold, rng=random.Random(seed))
    started = time.perf_counter()
    per_party, reference = build_inputs(
        n_mm=n_mm, n_real_mm=n_mm, n_parties=n_parties, is_real=1, n_requests=1,
        n_assets=1, ref_table=[market["ref"]], user_asset=0,
        user_qty=market["qty"], user_dir=0, user_entity=0, now_t=1,
        ref_mid=market["ref"], seed=seed, deal_hook=dealer)
    deal_ms = (time.perf_counter() - started) * 1e3
    return dealer, dealer.bound(), per_party, reference, deal_ms


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mp-spdz-root", type=Path, default=None)
    ap.add_argument("--n-mm", type=int, default=8)
    ap.add_argument("--n-parties", type=int, default=7)
    ap.add_argument("--threshold", type=int, default=2)
    ap.add_argument("--qty", type=int, default=20)
    ap.add_argument("--bit-length", type=int, default=31)
    ap.add_argument("--seed", type=int, default=5)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--out", type=Path, default=ROOT / "artifacts" / "binding_chain.json")
    args = ap.parse_args()

    group = make_group("ed25519")
    market = {"ref": 100000, "qty": args.qty}
    out = {"host": this_host(), "n_mm": args.n_mm, "n_parties": args.n_parties,
           "threshold": args.threshold, "prime": str(ED25519_ORDER),
           "prime_bits": ED25519_ORDER.bit_length(), "group": "ed25519"}

    # --- the honest arm --------------------------------------------------
    dealer, bound, per_party, reference, deal_ms = deal_market(
        group, args.n_mm, args.n_parties, args.threshold, args.seed, market)
    assert bound.party_file(0) == per_party[0]

    started = time.perf_counter()
    failures = check_all(dealer.key, bound)
    check_ms = (time.perf_counter() - started) * 1e3
    n_checks = len(bound.values) * args.n_parties

    # the venue's band, proved without opening anything. One field is enough to
    # show the link; the audit proves all of them and is measured separately.
    half_position = 5 + 1 + FIELDS.index("half")
    half_value = reconstruct(bound, half_position)
    started = time.perf_counter()
    band = PolicyBounds().half
    proof = dealer.prove_range(half_position, half_value, *band, context=b"band")
    range_ms = (time.perf_counter() - started) * 1e3
    bound = dealer.bound(ranges={half_position: proof})

    out["honest"] = {
        "values": len(bound.values), "deal_ms": round(deal_ms, 1),
        "share_checks": n_checks, "check_ms": round(check_ms, 1),
        "check_ms_each": round(check_ms / n_checks, 3),
        "failures": len(failures),
        "party_file_is_the_dealt_share": bound.party_file(0) == per_party[0],
        "rebuilt_request": [reconstruct(bound, i) for i in range(5)],
        "range_proof_ms": round(range_ms, 1),
        "band": list(band), "half_in_band": half_value,
        "range_verifies": check_range(dealer.key, bound, half_position, *band,
                                      context=b"band"),
        "lagrange": [str(c) for c in lagrange_at_zero(args.n_parties,
                                                      ED25519_ORDER)],
    }

    # --- a dealer that commits to one policy and deals another -----------
    liar, liar_bound, liar_files, _, _ = deal_market(
        group, args.n_mm, args.n_parties, args.threshold, args.seed, market)
    moved = 5 + 1 + FIELDS.index("half")
    tampered = list(liar_bound.values)
    swapped = tampered[moved]
    tampered[moved] = type(swapped)(
        position=swapped.position, commitment=swapped.commitment,
        shares=tuple(type(sh)(sh.party, sh.value_share + 1, sh.blinding_share)
                     if i == 3 else sh for i, sh in enumerate(swapped.shares)),
        label=swapped.label)
    caught = [(party, position) for party, position in
              check_all(liar.key, type(liar_bound)(
                  prime=liar_bound.prime, n_parties=liar_bound.n_parties,
                  threshold=liar_bound.threshold, values=tuple(tampered)))]
    out["dealer_that_deals_what_it_did_not_commit"] = {
        "moved_position": moved, "moved_party": 3,
        "caught": caught,
        "caught_before_computing": bool(caught),
    }

    # --- a node that feeds something else --------------------------------
    out["node_that_feeds_something_else"] = {
        "caught_by_this_chain": False,
        "why": "an input the node substitutes is still a valid share of a "
               "different number, and every commitment it opens still opens. "
               "That is zk/input_check.py, which catches the node where this "
               "catches the dealer. Neither implies the other.",
    }

    # --- the circuit ------------------------------------------------------
    root = args.mp_spdz_root
    if root is None or not (root / "malicious-shamir-party.x").exists():
        out["circuit"] = {"ran": False,
                          "why": "no malicious-shamir-party.x; pass --mp-spdz-root"}
        args.out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(out, indent=2))
        return 0

    work = Path(tempfile.mkdtemp(prefix="qomm-binding-"))
    padded = 1
    while padded < args.n_mm:
        padded *= 2
    source = build_program(
        n_mm=padded, n_parties=args.n_parties, mode="rfq", rfs_steps=1,
        disclose="none", now_t=1, ref_mid=market["ref"], band_bps=0,
        threshold_k=0, threshold_v=0, public_check=True, n_requests=1,
        n_assets=1, ref_table=[market["ref"]],
        maker_assets=[0] * padded, bit_length=args.bit_length,
        lagrange=lagrange_at_zero(args.n_parties, ED25519_ORDER))
    (work / "program.mpc").write_text(source, encoding="utf-8")
    inputs = work / "inputs"
    inputs.mkdir()
    # the files are the dealer's shares, written out unchanged
    for party in range(args.n_parties):
        (inputs / f"Input-P{party}-0").write_text(
            " ".join(str(v) for v in bound.party_file(party)) + "\n",
            encoding="utf-8")

    finish_reference(reference, padded=padded, bit_length=args.bit_length,
                     ref_table=[market["ref"]], is_real=1, n_assets=1,
                     user_asset=0, real_mm=args.n_mm, mode="rfq")
    program = f"qomm_binding_{int(time.time())}"
    run = MPSpdzRun(root, program, args.n_parties, args.threshold)
    run.extra_args += ["-P", str(ED25519_ORDER)]
    run.install(work / "program.mpc", inputs)
    run.compile(prime=ED25519_ORDER)
    samples, verdicts = [], []
    for _ in range(args.repeats):
        result = run.execute(0.0)
        if not result["ok"]:
            out["circuit"] = {"ran": False, "why": "a party failed"}
            break
        ok, detail = verify("rfq", result["log"], reference)
        verdicts.append((ok, detail))
        samples.append({"rounds": result["party0_rounds"],
                        "global_mb": result["global_mb"],
                        "wall_s": result["wall_seconds"]})
    else:
        out["circuit"] = {
            "ran": True,
            "verified": all(ok for ok, _ in verdicts),
            "detail": verdicts[0][1],
            "rounds": samples[0]["rounds"],
            "global_mb": samples[0]["global_mb"],
            "wall_s_median": statistics.median(s["wall_s"] for s in samples),
            "repeats": args.repeats,
        }
    shutil.rmtree(work, ignore_errors=True)
    args.out.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
