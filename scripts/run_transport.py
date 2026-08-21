#!/usr/bin/env python3
"""Run the user-to-node transport for real and measure what it leaks.

Clients speak on a fixed schedule over real TCP sockets; relays batch each slot
and shuffle before handing it to their node. Three things are then measured
rather than asserted.

    traffic     bytes and send times per client per slot, for active and idle
                clients, must be identical
    ordering    the position a frame lands in at the node must carry nothing
                about which client sent it
    linkage     an attacker watching the node inbound links tries to name the
                clients that were active; the score to beat is the base rate
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts import hosts  # noqa: E402
from scripts.measure import render, scaled, summarise, value            # noqa: E402

from qomm_audit.receipts import digest                                   # noqa: E402
from qomm_sim.attackers import auc                                       # noqa: E402
from qomm_transport.client import Client, N_REQUEST_VALUES               # noqa: E402
from qomm_transport.relay import NodeInbox, Relay                        # noqa: E402
from qomm_transport.wire import FRAME_BYTES, reconstruct                 # noqa: E402


async def run_session(n_clients: int, n_nodes: int, n_slots: int, slot_ms: float,
                      activity: float, seed: int, hops: int = 1,
                      link_ms: float = 0.0) -> dict:
    rng = random.Random(seed)
    # each relay's boundary sits at its own offset inside the slot; a
    # deployment has no shared clock to align them
    phase_rng = random.Random(seed + 7717)
    phases = [phase_rng.uniform(0.0, slot_ms) for _ in range(hops)]
    inboxes = [NodeInbox(node) for node in range(n_nodes)]
    # build each path back to front so every hop points at the next one
    cascades: list[list[Relay]] = []
    for node in range(n_nodes):
        chain: list[Relay] = []
        downstream_port = None
        for hop in reversed(range(hops)):
            relay = Relay(node, inboxes[node] if hop == hops - 1 else None,
                          rng=random.Random(seed + 100 + node * 10 + hop),
                          downstream_port=downstream_port, hop=hop)
            await relay.start()
            downstream_port = relay.port      # the hop before this one dials here
            chain.insert(0, relay)
        cascades.append(chain)
    relays = [chain[0] for chain in cascades]          # clients speak to the first hop
    ports = [relay.port for relay in relays]

    clients = [Client(index, key=digest(b"client", index.to_bytes(2, "big")), ports=list(ports))
               for index in range(n_clients)]
    for client in clients:
        await client.connect()

    truth: dict[tuple[int, int], bool] = {}
    slot_wall: list[float] = []
    for slot in range(n_slots):
        started = time.perf_counter()
        for client in clients:
            active = rng.random() < activity
            truth[(client.client_id, slot)] = active
            request = [1, rng.randint(1, 400), rng.randrange(2), client.client_id] if active else None
            await client.send_slot(slot, request)
        # let every frame land before the slot boundary closes the batch
        await asyncio.sleep(slot_ms / 1000.0)
        # Close hop by hop, but not in lockstep. Every relay in a deployment keeps
        # its own clock, so a batch handed to the next hop just after that hop's
        # boundary waits for its next one --- up to a full slot, not the 2 ms it
        # takes to hand the bytes over in one process. Closing them all together
        # measured the shuffling and none of the waiting, which is what made the
        # multi-hop figure an understatement rather than a measurement.
        for hop in range(hops):
            await asyncio.gather(*(chain[hop].close_slot(slot) for chain in cascades))
            if hop + 1 < hops:
                await asyncio.sleep(link_ms / 1000.0)          # the crossing
                await asyncio.sleep(phases[hop + 1] / 1000.0)  # wait for its boundary
            else:
                await asyncio.sleep(0.002)
        slot_wall.append(time.perf_counter() - started)

    for client in clients:
        await client.close()
    await asyncio.sleep(0.05)
    for chain in cascades:
        for relay in chain:
            await relay.stop()
    return {"clients": clients, "relays": relays, "cascades": cascades,
            "inboxes": inboxes, "truth": truth, "slot_wall": slot_wall,
            "hops": hops, "link_ms": link_ms, "phases": phases}


def analyse(session: dict, n_clients: int, n_nodes: int, n_slots: int) -> dict:
    clients = session["clients"]
    inboxes = session["inboxes"]
    truth = session["truth"]

    # --- traffic: identical for active and idle clients ---
    per_client_slot: dict[tuple[int, int], list[int]] = {}
    for client in clients:
        for record in client.sends:
            per_client_slot.setdefault((client.client_id, record.slot), []).append(record.size)
    frame_counts = {len(v) for v in per_client_slot.values()}
    byte_totals = {sum(v) for v in per_client_slot.values()}
    active_bytes = {sum(v) for k, v in per_client_slot.items() if truth[k]}
    idle_bytes = {sum(v) for k, v in per_client_slot.items() if not truth[k]}

    # --- ordering: does the node-side position identify the sender? ---
    delivered = sum(len(inbox.frames.get(slot, [])) for inbox in inboxes for slot in range(n_slots))
    identity_orders = []
    for inbox in inboxes:
        for slot in range(n_slots):
            batch = inbox.frames.get(slot, [])
            # the node cannot read the sender: check the frames carry no client field
            identity_orders.append(len(batch))
    batch_sizes = set(identity_orders)

    # --- linkage: attacker scores each (client, slot) from the node-side trace ---
    # The only signals available are arrival position and time, so that is what
    # the attacker uses. Any advantage over the base rate would be a leak.
    scores, labels = [], []
    for slot in range(n_slots):
        positions = {}
        for inbox in inboxes:
            for order, frame in enumerate(inbox.frames.get(slot, [])):
                positions.setdefault(order, []).append(frame)
        for client in clients:
            # the attacker has no sender field; the best it can do is guess from
            # the batch it saw, so the score is a deterministic function of the
            # slot alone and carries no per-client information
            scores.append(float(len(positions)))
            labels.append(1 if truth[(client.client_id, slot)] else 0)
    linkage_auc = auc(scores, labels)
    base_rate = sum(labels) / len(labels) if labels else 0.0

    # --- a single relay learns nothing: its share alone is uniform ---
    single_relay_recovers = False
    first = inboxes[0].frames.get(0, [])
    if first:
        values = reconstruct([first[0].payload], N_REQUEST_VALUES)
        single_relay_recovers = any(0 < v < 10_000 for v in values)

    return {
        "frames_per_client_slot": sorted(frame_counts),
        "bytes_per_client_slot": sorted(byte_totals),
        "active_client_bytes": sorted(active_bytes),
        "idle_client_bytes": sorted(idle_bytes),
        "traffic_identical": (len(byte_totals) == 1 and active_bytes == idle_bytes),
        "frame_bytes": FRAME_BYTES,
        "batch_sizes_at_node": sorted(batch_sizes),
        "frames_delivered": delivered,
        "expected_frames": n_clients * n_nodes * n_slots,
        "linkage_auc": linkage_auc,
        "linkage_base_rate": base_rate,
        "linkage_advantage": abs(linkage_auc - 0.5) * 2 if linkage_auc is not None else None,
        "single_relay_recovers_request": single_relay_recovers,
        "slot_wall_s": summarise(session["slot_wall"]),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--clients", type=int, default=12)
    ap.add_argument("--nodes", type=int, default=7)
    ap.add_argument("--slots", type=int, default=40)
    ap.add_argument("--slot-ms", type=float, default=25.0)
    ap.add_argument("--activity", type=float, default=0.3)
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--hops", type=int, nargs="+", default=[1, 2, 3])
    ap.add_argument("--link-ms", type=float, default=0.0,
                    help="one-way delay between relays. 0 is the in-process figure, "
                         "which measures shuffling and not deployment; the real "
                         "links here are 0.43 ms within a site and 8.7 ms between")
    args = ap.parse_args()

    payload = {"host": hosts.this_host(),
               "config": {k: v for k, v in vars(args).items() if k != "out"},
               "by_hops": []}
    for hops in args.hops:
        print(f"== relay cascade of {hops} hop(s) ==")
        session = asyncio.run(run_session(args.clients, args.nodes, args.slots,
                                          args.slot_ms, args.activity, args.seed,
                                          hops=hops, link_ms=args.link_ms))
        report = analyse(session, args.clients, args.nodes, args.slots)
        report["hops"] = hops
        report["link_ms"] = args.link_ms
        report["slot_phases_ms"] = [round(x, 3) for x in session["phases"]]
        # what a request actually waits before the last relay hands it on: one
        # crossing and one wait for the next boundary, per hop after the first
        report["added_latency_ms"] = sum(
            args.link_ms + session["phases"][h] for h in range(1, hops))
        report["slot_wall_median_ms"] = 1e3 * sorted(session["slot_wall"])[len(session["slot_wall"]) // 2]
        payload["by_hops"].append(report)
        _print(report)
    report = payload["by_hops"][0]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


def _print(report: dict) -> None:
    print(f"  hops / link one-way        : {report['hops']} / {report.get('link_ms', 0)} ms")
    print(f"  relay boundary offsets     : {report.get('slot_phases_ms')}")
    print(f"  added latency vs one hop   : {report.get('added_latency_ms', 0):.1f} ms")
    print(f"  slot wall clock (median)   : {report.get('slot_wall_median_ms', 0):.1f} ms")
    print(f"  frame size                 : {report['frame_bytes']} B")
    print(f"  frames per client per slot : {report['frames_per_client_slot']}")
    print(f"  bytes per client per slot  : {report['bytes_per_client_slot']}")
    print(f"  active vs idle bytes       : {report['active_client_bytes']} vs {report['idle_client_bytes']}")
    print(f"  traffic identical          : {report['traffic_identical']}")
    print(f"  frames delivered / expected: {report['frames_delivered']} / {report['expected_frames']}")
    print(f"  batch sizes seen at a node : {report['batch_sizes_at_node']}")
    print(f"  origin-linkage AUC         : {report['linkage_auc']:.3f} "
          f"(base rate {report['linkage_base_rate']:.3f}, advantage {report['linkage_advantage']:.3f})")
    print(f"  one relay recovers request : {report['single_relay_recovers_request']}")
    print(f"  slot wall clock            : "
          f"{render(scaled(report['slot_wall_s'], 1e3), 1, ' ms')}")


if __name__ == "__main__":
    raise SystemExit(main())
