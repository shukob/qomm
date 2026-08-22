#!/usr/bin/env python3
"""Is the request the circuit priced the request the taker sent?

The maker publishes commitments to its policy. The taker sends a request. The
quote comes back. **Nothing so far in this repository has run a verification
across that seam**, and this does: it derives the coefficients from the
published commitments, hands the same list to the circuit, runs it, and checks
the openings the circuit produced against the commitments the input parties
published.

Two things it is for.

**Coverage.** `roles.Trader` and `roles.MarketMaker` are both `InputParty` and
the request is read through `secret_input()` exactly like a policy field, so the
per-party accumulator should fold it. Should is not the same as does, and a
substituted *request* share is the case that matters to a taker.

**Soundness across the seam.** `gen_qomm` has been emitting a fixture
coefficient list --- `1 + (617*k) % 63` --- with a comment saying a fixture
stands in for the Fiat--Shamir derivation. **With fixture coefficients the check
proves nothing**: the entire argument is that the coefficients arrive after the
commitments, so a node that knows them in advance picks its error to cancel.
This runner derives them properly and passes them in, which is what makes the
two halves the same statement rather than two statements that resemble each
other.

What it cannot establish, and says so in the artifact: that the maker's
committed policy is one it would honour, that the request was real (the maker
never sees it, by design), or that every eligible maker was included (an
omission has no commitment in the statement; `qomm_audit/receipts.py` covers
that on a different axis).
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mp_spdz.gen_qomm import FIELDS                                   # noqa: E402
from scripts.hosts import this_host                                   # noqa: E402
from scripts.measure import exact                                     # noqa: E402
from scripts.run_qomm import MPSpdzRun                                # noqa: E402
from zk.commit import Pedersen                                        # noqa: E402
from zk.groups import make_group                                      # noqa: E402
from zk.input_check import (PerPartyCheck, per_party_coefficients,    # noqa: E402
                            verify_per_party)
from zk.scheme import PedersenScheme                                  # noqa: E402

OPENING = re.compile(r"QOMM_PER_PARTY_CHECK_(\d+)_(\d+)=(-?\d+)")


def generate(work: Path, n_mm: int, n_parties: int, field_bits: int,
             coefficients: list[int] | None) -> tuple[Path, Path, dict]:
    """One call to the generator, with whatever coefficients we were given."""
    program, inputs, reference = (work / "p.mpc", work / "in",
                                  work / "reference.json")
    cmd = [sys.executable, str(ROOT / "mp_spdz" / "gen_qomm.py"),
           "--n-mm", str(n_mm), "--n-parties", str(n_parties),
           "--input-check", "--check-mode", "per-party", "--check-repeats", "1",
           "--field-bits", str(field_bits), "--seed", "7",
           "--out-program", str(program), "--out-input-dir", str(inputs),
           "--out-reference", str(reference)]
    if coefficients is not None:
        (work / "coeff.json").write_text(json.dumps(coefficients))
        cmd += ["--check-coefficients", str(work / "coeff.json")]
    done = subprocess.run(cmd, capture_output=True, text=True)
    if done.returncode:
        raise RuntimeError(done.stderr[-3000:])
    return program, inputs, json.loads(reference.read_text())


def read_inputs(directory: Path, n_parties: int) -> dict[int, list[int]]:
    return {p: [int(v) for v in
                (directory / f"Input-P{p}-0").read_text().split()]
            for p in range(n_parties)}


def run(root: Path, program: Path, per_party: dict[int, list[int]],
        n_parties: int, threshold: int, prime: int, tag: str) -> dict:
    job = MPSpdzRun(root, f"identity{tag}", n_parties, threshold)
    inputs = job.run_dir / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    for party, values in per_party.items():
        (inputs / f"Input-P{party}-0").write_text(
            "\n".join(str(v) for v in values) + "\n", encoding="utf-8")
    job.install(program, inputs)
    # The MPC field has to be the commitment's scalar field, or the openings
    # wrap and the check compares two different numbers. The first version of
    # this compiled at the default 128 bits and every party looked guilty ---
    # which is exactly the failure mode a verifier must not have.
    job.compile(prime=prime)
    job.extra_args += ["-P", str(prime)]
    result = job.execute(delay_ms=0.0)
    openings = {}
    for repeat, party, value in OPENING.findall(result.get("log", "")):
        openings[int(party)] = int(value)
    return {"openings": openings, "log_tail": result.get("log", "")[-400:]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, required=True)
    ap.add_argument("--n-mm", type=int, default=4)
    ap.add_argument("--parties", type=int, default=7)
    ap.add_argument("--threshold", type=int, default=2)
    ap.add_argument("--field-bits", type=int, default=253)
    ap.add_argument("--tamper-index", type=int, default=1,
                    help="which input to substitute. 1 is the taker's quantity, "
                         "which is the case a taker cares about.")
    ap.add_argument("--tamper-party", type=int, default=4)
    ap.add_argument("--out", type=Path,
                    default=ROOT / "artifacts" / "identity.json")
    args = ap.parse_args()

    scheme = PedersenScheme(Pedersen(make_group("ed25519"),
                                     b"qomm:pedersen:v1"))
    context = b"qomm:identity:v1"
    n_checked = 4 + 2 + args.n_mm * len(FIELDS)     # request, is_real, mask, policies

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        # First pass only to get the dealing. The coefficients affect the mask
        # WIDTH, so a placeholder of the intended width gives the same inputs
        # the real list will.
        placeholder = [(1 << 40) - 1] * n_checked
        _, inputs, reference = generate(work, args.n_mm, args.parties,
                                        args.field_bits, placeholder)
        per_party = read_inputs(inputs, args.parties)

        shares = [per_party[p][:n_checked] for p in range(args.parties)]
        masks = [per_party[p][n_checked] for p in range(args.parties)]

        # what the taker and the makers publish
        blindings = [[scheme.random_blinding() for _ in range(n_checked)]
                     for _ in range(args.parties)]
        mask_blindings = [scheme.random_blinding() for _ in range(args.parties)]
        commitments = [[scheme.commit(v, r) for v, r in zip(row, brow)]
                       for row, brow in zip(shares, blindings)]
        mask_commitments = [scheme.commit(m, b)
                            for m, b in zip(masks, mask_blindings)]

        # the coefficients come AFTER the commitments, which is the whole
        # soundness argument and the thing the fixture list threw away
        coefficients = per_party_coefficients(scheme, commitments,
                                              mask_commitments, context)
        program, inputs2, reference = generate(work, args.n_mm, args.parties,
                                               args.field_bits, coefficients)
        again = read_inputs(inputs2, args.parties)
        assert again == per_party, "the dealing changed with the coefficients"

        def check(openings: dict[int, int]) -> tuple[bool, str, list[int]]:
            blinds = [sum(c * r for c, r in zip(coefficients, blindings[p]))
                      + mask_blindings[p] for p in range(args.parties)]
            # the circuit prints the signed representative; the commitment
            # lives mod the group order, so bring them into the same ring
            return verify_per_party(
                scheme,
                PerPartyCheck(commitments, mask_commitments,
                              [openings[p] % scheme.scalar_modulus
                               for p in range(args.parties)],
                              blinds), context)

        prime = scheme.scalar_modulus
        honest = run(args.root, program, per_party, args.parties,
                     args.threshold, prime, "h")
        honest_verdict = check(honest["openings"])

        tampered_inputs = copy.deepcopy(per_party)
        tampered_inputs[args.tamper_party][args.tamper_index] += 1
        tampered = run(args.root, program, tampered_inputs, args.parties,
                       args.threshold, prime, "t")
        tampered_verdict = check(tampered["openings"])

    result = {
        "host": this_host(),
        "question": ("Is the request the circuit priced the request the taker "
                     "sent, and is the policy the one the maker published?"),
        "setting": {"n_makers": args.n_mm, "n_parties": args.parties,
                    "threshold": args.threshold, "field_bits": args.field_bits,
                    "checked_values": n_checked, "repeats": 1},
        "the_seam_that_was_open": (
            "gen_qomm emitted a FIXTURE coefficient list with a comment saying so. "
            "With fixture coefficients the check proves nothing --- the argument "
            "is entirely that the coefficients arrive after the commitments, so a "
            "node knowing them in advance picks its error to cancel. This run "
            "derives them from the published commitments and hands the same list "
            "to the circuit, which is the first time a verification has run "
            "across that seam."),
        "honest": {"verified": honest_verdict[0], "culprits": honest_verdict[2],
                   "openings": {str(k): v for k, v in honest["openings"].items()}},
        "tampered": {
            "what": (f"node {args.tamper_party} fed a different value at input "
                     f"{args.tamper_index}, which is the taker's quantity --- the "
                     f"case a taker cares about rather than a maker"),
            "verified": tampered_verdict[0],
            "named": tampered_verdict[2],
            "named_the_right_node": tampered_verdict[2] == [args.tamper_party],
            "message": tampered_verdict[1]},
        "what_this_does_not_establish": [
            "That the maker's committed policy is one it would honour off-venue. "
            "policy_audit shows the fields sit in bands the venue published; it "
            "cannot show intent.",
            "That the request was real. The maker never sees it --- that is the "
            "design --- so it cannot tell a genuine request from probing, which "
            "is what is_real cover traffic and the disclosure budget are for.",
            "That every eligible maker was included. An omission has no "
            "commitment in the statement to fail against; qomm_audit/receipts.py "
            "covers that per slot, on a different axis."],
    }
    print(f"honest run:   verified={honest_verdict[0]} culprits={honest_verdict[2]}")
    print(f"node {args.tamper_party} substitutes the taker's quantity:")
    print(f"  verified={tampered_verdict[0]}  named={tampered_verdict[2]}")
    print(f"  {tampered_verdict[1]}")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"wrote {args.out}")
    return 0 if (honest_verdict[0]
                 and tampered_verdict[2] == [args.tamper_party]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
