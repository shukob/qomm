#!/usr/bin/env python3
"""Drive fixed-schedule slots through the real MPC and audit the computing nodes.

Two questions are answered with measurements rather than assertions.

1. Is a cover slot indistinguishable from a real one on the wire? The circuit is
   run with the secret real/cover flag set both ways and the compiler statistics,
   the round count, the byte count and the wall time are compared.

2. Do the three audit mechanisms actually convict? Faults are injected into the
   receipt stream -- a node that signs two results, one that drops an eligible
   maker, one that reuses an old state, one that goes silent -- and the ledger
   has to name each of them without being told which is which.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from scripts import hosts  # noqa: E402

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from qomm_audit.receipts import (                                                # noqa: E402
    GENESIS, AuditLedger, BondLedger, Fault, NodeReceipt, SlotSpec, digest, sign_receipt,
)


def run_slot(root: Path, *, is_real: int, mode: str, n_mm: int, bit_length: int,
             delay_ms: float, repeats: int, seed: int) -> dict:
    cmd = [sys.executable, str(HERE / "run_qomm.py"), "--mp-spdz-root", str(root),
           "--mode", mode, "--n-mm", str(n_mm), "--bit-length", str(bit_length),
           "--delay-ms", str(delay_ms), "--repeats", str(repeats),
           "--is-real", str(is_real), "--seed", str(seed)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": "unparseable", "stderr": proc.stderr[-1500:], "is_real": is_real}
    circuit = payload.get("circuit", {})
    circuit.pop("compile_log", None)
    return payload


def indistinguishability(root: Path, args) -> dict:
    """Same circuit, secret flag flipped. Anything that differs is a leak."""
    rows = []
    for is_real in (1, 0):
        for trial in range(args.trials):
            row = run_slot(root, is_real=is_real, mode=args.mode, n_mm=args.n_mm,
                           bit_length=args.bit_length, delay_ms=args.delay_ms,
                           repeats=args.repeats, seed=args.seed + trial)
            rows.append(row)
            print(f"  slot is_real={is_real} trial={trial}: "
                  f"rounds={row.get('measured_rounds')} mb={row.get('measured_mb')} "
                  f"median={row.get('wall_median')} ok={row.get('verified')}", flush=True)

    real = [r for r in rows if r.get("is_real") == 1 and r.get("verified")]
    cover = [r for r in rows if r.get("is_real") == 0 and r.get("verified")]
    if not real or not cover:
        return {"error": "a slot failed to verify", "rows": rows}

    def field(rows_, key):
        return sorted({r.get(key) for r in rows_})

    def circuit_field(rows_, key):
        return sorted({r.get("circuit", {}).get(key) for r in rows_})

    identical = {
        "vm_rounds": circuit_field(real, "vm_rounds") == circuit_field(cover, "vm_rounds"),
        "integer_triples": circuit_field(real, "integer_triples") == circuit_field(cover, "integer_triples"),
        "measured_rounds": field(real, "measured_rounds") == field(cover, "measured_rounds"),
        "measured_mb": field(real, "measured_mb") == field(cover, "measured_mb"),
    }
    real_times = [r["wall_median"] for r in real]
    cover_times = [r["wall_median"] for r in cover]
    return {
        "identical": identical,
        "all_identical": all(identical.values()),
        "real": {"rounds": field(real, "measured_rounds"), "mb": field(real, "measured_mb"),
                 "median_s": statistics.median(real_times), "n": len(real)},
        "cover": {"rounds": field(cover, "measured_rounds"), "mb": field(cover, "measured_mb"),
                  "median_s": statistics.median(cover_times), "n": len(cover)},
        "timing_gap_s": abs(statistics.median(real_times) - statistics.median(cover_times)),
        "timing_spread_s": max(max(real_times) - min(real_times),
                               max(cover_times) - min(cover_times)),
        "rows": rows,
    }


def audit_drill(n_nodes: int, n_slots: int, quorum: int) -> dict:
    """Inject one fault per kind and check the ledger names the right node."""
    keys = {node: Ed25519PrivateKey.generate() for node in range(n_nodes)}
    ledger = AuditLedger({node: key.public_key() for node, key in keys.items()})
    bonds = BondLedger({node: 2_000_000 for node in range(n_nodes)})

    fixed_makers = digest(b"makers", *[f"MM-{i}".encode() for i in range(16)])
    injected = {
        (2, 1): Fault.EQUIVOCATION,
        (3, 2): Fault.OMITTED_MAKERS,
        (4, 3): Fault.STALE_STATE,
        (5, 4): Fault.MISSING_RECEIPT,
    }

    prev = GENESIS
    timeline = []
    for slot in range(n_slots):
        spec = SlotSpec(slot=slot, mm_set_digest=fixed_makers,
                        market_digest=digest(b"market", slot.to_bytes(4, "big")),
                        deadline=100 * slot + 50, required_receipts=quorum)
        ledger.open_slot(spec)
        # every slot carries a result digest, real or cover; the audit cannot tell
        result = digest(b"result", slot.to_bytes(4, "big"))
        new_state = digest(b"state", prev, result)

        for node in range(n_nodes):
            fault = injected.get((node, slot))
            if fault is Fault.MISSING_RECEIPT:
                continue                                    # silent node
            makers = fixed_makers
            parent = prev
            if fault is Fault.OMITTED_MAKERS:
                makers = digest(b"makers", *[f"MM-{i}".encode() for i in range(15)])
            if fault is Fault.STALE_STATE and slot >= 1:
                parent = GENESIS                            # reuses a superseded state
            ledger.record(sign_receipt(
                keys[node], node, spec, prev_state_digest=parent,
                new_state_digest=new_state, result_digest=result,
                emitted_at=100 * slot + 10, mm_set_digest=makers))
            if fault is Fault.EQUIVOCATION:
                other = digest(b"state", prev, digest(b"result-other"))
                ledger.record(sign_receipt(
                    keys[node], node, spec, prev_state_digest=parent,
                    new_state_digest=other, result_digest=digest(b"result-other"),
                    emitted_at=100 * slot + 11))

        settled, found = ledger.settle(slot, now=100 * slot + 60)
        prev = settled if settled is not None else prev
        timeline.append({"slot": slot, "settled": settled.hex()[:16] if settled else None,
                         "new_findings": [e.as_dict() for e in found]})

    caught = {(e.node, e.slot, e.fault) for e in ledger.evidence}
    expected = {(node, slot, fault) for (node, slot), fault in injected.items()}
    # A node that equivocates also signs a state the quorum rejects, so it is
    # convicted twice for one act. That is a consequence of the injected fault,
    # not a finding against an honest node, and is counted separately.
    guilty_slots = set(injected)
    consequential = [e.as_dict() for e in ledger.evidence
                     if e.node >= 0 and (e.node, e.slot, e.fault) not in expected
                     and (e.node, e.slot) in guilty_slots]
    wrongful = [e.as_dict() for e in ledger.evidence
                if e.node >= 0 and (e.node, e.slot) not in guilty_slots]
    slashing = bonds.apply(ledger.evidence)
    return {
        "nodes": n_nodes, "slots": n_slots, "quorum": quorum,
        "injected": [{"node": n, "slot": s, "fault": f.value}
                     for (n, s), f in sorted(injected.items())],
        "detected_all_injected": expected.issubset(caught),
        "missed": [{"node": n, "slot": s, "fault": f.value}
                   for (n, s, f) in sorted(expected - caught, key=str)],
        "evidence": [e.as_dict() for e in ledger.evidence],
        "consequential_findings": consequential,
        "wrongful_findings": wrongful,
        "slashing": slashing,
        "remaining_bonds": bonds.bonds,
        "timeline": timeline,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mp-spdz-root", type=Path,
                    default=Path(os.environ.get("MP_SPDZ_ROOT", "")))
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--mode", default="rfs")
    ap.add_argument("--n-mm", type=int, default=16)
    ap.add_argument("--bit-length", type=int, default=31)
    ap.add_argument("--delay-ms", type=float, default=1.0)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--nodes", type=int, default=7)
    ap.add_argument("--slots", type=int, default=6)
    ap.add_argument("--quorum", type=int, default=5)
    ap.add_argument("--skip-mpc", action="store_true")
    args = ap.parse_args()

    payload = {"host": hosts.this_host(),
               "config": vars(args) | {"mp_spdz_root": str(args.mp_spdz_root),
                                       "out": str(args.out)}}
    if not args.skip_mpc:
        print("== cover slot vs real slot on the wire ==", flush=True)
        payload["indistinguishability"] = indistinguishability(args.mp_spdz_root, args)
        summary = payload["indistinguishability"]
        if "identical" in summary:
            print(f"  identical: {summary['identical']}  "
                  f"timing gap {summary['timing_gap_s']:.4f}s vs spread "
                  f"{summary['timing_spread_s']:.4f}s", flush=True)

    print("== audit drill ==", flush=True)
    payload["audit_drill"] = audit_drill(args.nodes, args.slots, args.quorum)
    drill = payload["audit_drill"]
    print(f"  injected {len(drill['injected'])} faults, "
          f"detected_all={drill['detected_all_injected']}, "
          f"missed={drill['missed']}, "
          f"wrongful={len(drill['wrongful_findings'])} "
          f"(consequential={len(drill['consequential_findings'])})", flush=True)
    for record in drill["slashing"]:
        print(f"    slashed node {record['node']} slot {record['slot']} "
              f"{record['fault']}: {record['amount']}", flush=True)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n",
                        encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
