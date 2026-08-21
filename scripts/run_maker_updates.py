#!/usr/bin/env python3
"""How often a market maker can change its mind.

The pricing parameters are secret inputs, not a standing registration, so a
maker changes its quote by dealing new shares --- not by any interaction with
the protocol. That makes the update rate a property of the dealing path alone,
and the dealing path is small: a share is one integer, and a full policy is nine
of them across seven nodes.

Which means bandwidth cannot be the limit, and the question is what the
authentication costs. Three arms, because the repository already treats these as
three different guarantees:

    split only        shares that sum to the value, and nothing that says who
                      dealt them. No attribution.
    signed            each share signed, so a node that inputs something else
                      can be shown to have done it. Detection and attribution,
                      not prevention.
    signed+committed  the same, plus a commitment to every share and to the
                      value, so a *dealer* that deals shares which do not add up
                      cannot publish the dealing without saying so.

Two scopes, because a maker changing its view and a maker changing its whole
policy are different events: nine fields against one.

Both sides are measured, because only the smaller of the two is the rate. A
maker deals to seven nodes but a node is dealt to by every maker, so a node
doing M times the work at 1/M the rate is the constraint even when the maker
looks fast.

Reconstruction is checked on every arm. A rate for an update that did not
survive reconstruction is not a rate.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qomm_transport.roles import (ComputingNode, MarketMaker,          # noqa: E402
                                  check_field_width, check_share, dealt_body,
                                  split)
from scripts.hosts import this_host                                    # noqa: E402
from scripts.measure import exact, render, summarise                   # noqa: E402
from zk.commit import Pedersen                                         # noqa: E402
from zk.groups import make_group                                       # noqa: E402

# what a maker registers, in the order the circuit reads it
POLICY = {"asset": 0, "mid": 37, "half": 22, "slope": 2, "invcoef": 1,
          "inv": -140, "maxqty": 500, "expiry": 900_000, "active": 1}
VIEW = {"mid": 37}


def wire_bytes(name: str, n_nodes: int, n_fields: int, signed: bool,
               committed: bool, group=None) -> int:
    """One update as it goes out, counted rather than estimated.

    The unsigned arm carries no signature, which the first version of this
    counted anyway and so reported the three arms as costing the same.
    """
    body = len(dealt_body(name, 0, 0, 12345))
    signature = 64 if signed else 0                   # Ed25519
    per_share = body + signature
    total = per_share * n_nodes * n_fields
    if committed:
        point = len(group.encode(group.base_pow(1)))
        blinding = 32
        # one commitment per share, one per value, and the blinding each node
        # needs to open its own
        total += n_fields * ((n_nodes + 1) * point + n_nodes * blinding)
    return total


def one_update(maker: MarketMaker, nodes: list[ComputingNode], fields: dict,
               arm: str, key) -> None:
    if arm == "split only":
        for value in fields.values():
            for node, share in zip(nodes, split(value, maker.n_nodes,
                                                maker.value_bits)):
                node.receive(share)
    elif arm == "signed":
        maker.deal(fields.values(), nodes)
    elif arm == "signed+committed":
        for value in fields.values():
            maker.deal_committed(value, nodes, key)
    else:
        raise ValueError(arm)


def node_side(maker: MarketMaker, fields: dict, arm: str, key,
              n_nodes: int) -> tuple[float, bool]:
    """What one node pays to accept one maker's update, and whether it accepts.

    A node checks only its own share: one signature per field, and where the
    dealing is committed, one commitment opening per field as well.
    """
    verify_key = maker.signing_key.public_key()
    prepared = []
    for position, value in enumerate(fields.values()):
        if arm == "signed+committed":
            # the shares have to be the ones `deal_committed` actually
            # committed to, so they are read back off the nodes it dealt to
            # rather than drawn again --- a second `split` gives different
            # shares, the check fails, and `and` then short-circuits past the
            # expensive part, which is how this first reported the committed
            # arm as faster than the signed one.
            dealt = [ComputingNode(index=i) for i in range(n_nodes)]
            dealing, blindings = maker.deal_committed(value, dealt, key)
            prepared.append((position, dealt[0].inputs[0], dealing, blindings[0]))
        else:
            shares = split(value, n_nodes, maker.value_bits)
            body = dealt_body(maker.name, 0, position, shares[0])
            signature = maker.signing_key.sign(body)
            prepared.append((position, shares[0], body, signature))

    failures = 0
    start = time.perf_counter()
    for position, share, second, third in prepared:
        if arm == "split only":
            continue
        if arm == "signed":
            try:
                verify_key.verify(third, second)
            except Exception:
                failures += 1
        else:
            # every check runs, and the verdict is taken afterwards: an `and`
            # here would stop paying for the checks as soon as one failed and
            # time a node that had given up.
            adds_up = second.adds_up(key)
            opens = check_share(key, second, 0, share, third)
            failures += not (adds_up and opens)
    elapsed = time.perf_counter() - start
    return elapsed, failures == 0


def reconstructs(nodes: list[ComputingNode], fields: dict, n_nodes: int) -> bool:
    """Every field read back out of the nodes, in the order it was dealt."""
    if any(len(node.inputs) != len(fields) for node in nodes):
        return False
    for position, value in enumerate(fields.values()):
        if sum(node.inputs[position] for node in nodes) != value:
            return False
    return True


def measure(arm: str, fields: dict, n_nodes: int, value_bits: int,
            repeats: int, key) -> dict:
    maker = MarketMaker(name="mm-00", n_nodes=n_nodes, value_bits=value_bits,
                        signing_key=Ed25519PrivateKey.generate())
    seconds, verified = [], True
    for _ in range(repeats):
        nodes = [ComputingNode(index=i) for i in range(n_nodes)]
        start = time.perf_counter()
        one_update(maker, nodes, fields, arm, key)
        seconds.append(time.perf_counter() - start)
        verified = verified and reconstructs(nodes, fields, n_nodes)
    node_seconds, node_accepted = [], True
    for _ in range(max(1, repeats // 4)):
        elapsed, accepted = node_side(maker, fields, arm, key, n_nodes)
        node_seconds.append(elapsed)
        node_accepted = node_accepted and accepted
    rates = [1.0 / s for s in seconds]
    node_rates = [1.0 / s for s in node_seconds if s > 0]
    return {"arm": arm, "fields": len(fields),
            "seconds": summarise(seconds), "updates_per_second": summarise(rates),
            "node_seconds": summarise(node_seconds),
            "node_updates_per_second_per_core": (
                summarise(node_rates) if node_rates else None),
            "node_accepted": node_accepted,
            "bytes_on_the_wire": exact(
                wire_bytes(maker.name, n_nodes, len(fields),
                           arm != "split only",
                           arm == "signed+committed", key.group)),
            "verified": verified}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path,
                    default=ROOT / "artifacts" / "maker_updates.json")
    ap.add_argument("--n-nodes", type=int, default=7)
    ap.add_argument("--value-bits", type=int, default=32)
    ap.add_argument("--field-bits", type=int, default=128)
    ap.add_argument("--repeats", type=int, default=200)
    ap.add_argument("--group", default="ed25519")
    ap.add_argument("--makers", type=int, default=16,
                    help="a node is dealt to by every maker, so its per-core "
                         "rate is shared out among them")
    args = ap.parse_args()

    check_field_width(args.n_nodes, args.value_bits, args.field_bits)
    key = Pedersen(make_group(args.group), b"qomm:maker-update:v1")

    result = {"host": this_host(), "n_nodes": args.n_nodes,
              "value_bits": args.value_bits, "group": args.group,
              "repeats": args.repeats, "n_makers": args.makers,
              "note": "node rates are one core. Verification is per-share and "
                      "independent, so a node with more cores scales; the maker "
                      "side does not, because one maker is one dealer.",
              "policy_fields": list(POLICY), "rows": []}
    for scope, fields in (("full policy", POLICY), ("view only", VIEW)):
        for arm in ("split only", "signed", "signed+committed"):
            row = measure(arm, fields, args.n_nodes, args.value_bits,
                          args.repeats, key)
            row["scope"] = scope
            node = row["node_updates_per_second_per_core"]
            # the ceiling a maker actually sees: it cannot deal faster than it
            # can sign, and it cannot be accepted faster than a node --- busy
            # with every other maker too --- can check.
            row["sustainable_per_maker"] = min(
                row["updates_per_second"]["median"],
                node["median"] / args.makers) if node else None
            result["rows"].append(row)
            node = row["node_updates_per_second_per_core"]
            print(f"{scope:12} {arm:17} "
                  f"maker {render(row['updates_per_second'], 0, '/s'):>20}  "
                  f"node {render(node, 0, '/s') if node else 'n/a':>20}  "
                  f"{row['bytes_on_the_wire']['exact']:>6} B  "
                  f"ok={row['verified'] and row['node_accepted']}", flush=True)
            if row["sustainable_per_maker"]:
                print(f"{'':12} {'':17} -> with {args.makers} makers, "
                      f"{row['sustainable_per_maker']:.0f} updates/s each",
                      flush=True)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"\nwrote {args.out}")
    return 0 if all(row["verified"] for row in result["rows"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
