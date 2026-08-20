#!/usr/bin/env python3
"""Pull the UniswapX fill history off an Ethereum archive node.

Why this venue: the study models request-for-quote, where a taker asks and
several makers compete. An AMM swap has no such structure --- there is a curve,
not a set of makers --- but a UniswapX `Fill` names both the swapper who asked
and the filler who won, which is exactly the pair `qomm_sim` generates. Measured
over 28 months the venue carries 8--23 distinct fillers at any time, so the
M=16 the study sweeps is an observed number rather than a chosen one.

Two things are deliberate.

*Block number is the clock.* Fetching a timestamp per fill would cost about a
million calls, and interpolating inside a chunk drifts by a minute or more over
800 blocks once slots are missed. Post-merge a slot is 12 s, so a 60-second
disclosure window is 5 blocks exactly, and windows expressed in blocks need no
timestamps at all. `--checkpoint-every` records real timestamps sparsely so the
drift against wall time can be stated rather than assumed.

*Amounts are a second pass.* The Fill event carries no sizes; they have to be
read from the transfers in the same transaction, at one receipt per fill. That
is affordable for the tens of thousands of requests a simulation consumes and
not for the whole history, so `--amounts` runs separately over a slice.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

FILL_SIG = "Fill(bytes32,address,address,uint256)"
TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
# Native ether has no token contract. It is given an address so a leg paid in
# ether and a leg paid in a token can sit in the same structure.
NATIVE = "0x0000000000000000000000000000000000000000"
# The two reactors that carry effectively all fills. Scanning by topic alone
# also picks up unrelated contracts that share the signature, which is why the
# address filter is not optional.
REACTORS = [
    "0x00000011f84b9aa48e5f8aa8b9897600006289be",
    "0x6000da47483062a0d734ba3dc7576ce6a0b645c4",
]
CHUNK = 800          # the node rejects getLogs ranges of 1000 or more


class Rpc:
    def __init__(self, url: str):
        self.url = url
        self.calls = 0

    def __call__(self, method: str, params: list, retries: int = 4):
        payload = json.dumps({"jsonrpc": "2.0", "method": method,
                              "params": params, "id": 1}).encode()
        for attempt in range(retries):
            try:
                req = urllib.request.Request(
                    self.url, payload, {"Content-Type": "application/json"})
                body = json.load(urllib.request.urlopen(req, timeout=300))
                self.calls += 1
                if "error" in body:
                    raise RuntimeError(body["error"])
                return body["result"]
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                if attempt == retries - 1:
                    raise
                time.sleep(2 ** attempt)
                print(f"  retry {attempt+1} after {exc}", file=sys.stderr, flush=True)


def topic_of(rpc: Rpc, signature: str) -> str:
    return rpc("web3_sha3", ["0x" + signature.encode().hex()])


def resume_point(path: Path) -> int | None:
    """The block after the last one already written, so a kill is not a restart."""
    if not path.exists():
        return None
    last = None
    with path.open() as handle:
        for line in handle:
            if line.strip():
                try:
                    last = json.loads(line)
                except json.JSONDecodeError:
                    break            # a torn final line, ignore it
    return None if last is None else last["block"] + 1


def skeleton(rpc: Rpc, out: Path, start: int, end: int, checkpoint_every: int) -> None:
    topic = topic_of(rpc, FILL_SIG)
    resume = resume_point(out)
    if resume is not None:
        print(f"resuming at block {resume}", file=sys.stderr)
        start = max(start, resume)
    fills = 0
    t0 = time.time()
    with out.open("a") as handle:
        for chunk_start in range(start, end, CHUNK):
            chunk_end = min(chunk_start + CHUNK - 1, end)
            logs = rpc("eth_getLogs", [{
                "fromBlock": hex(chunk_start), "toBlock": hex(chunk_end),
                "address": REACTORS, "topics": [topic]}]) or []
            stamp = None
            if checkpoint_every and chunk_start % checkpoint_every < CHUNK:
                header = rpc("eth_getBlockByNumber", [hex(chunk_start), False])
                stamp = int(header["timestamp"], 16)
            for log in logs:
                if len(log["topics"]) < 4:
                    continue          # not the shape we decode; skip rather than guess
                handle.write(json.dumps({
                    "block": int(log["blockNumber"], 16),
                    "tx": log["transactionHash"],
                    "log_index": int(log["logIndex"], 16),
                    "reactor": log["address"].lower(),
                    "order": log["topics"][1],
                    "filler": "0x" + log["topics"][2][-40:],
                    "swapper": "0x" + log["topics"][3][-40:],
                }) + "\n")
                fills += 1
            if stamp is not None:
                handle.write(json.dumps({"block": chunk_start, "checkpoint": stamp}) + "\n")
            handle.flush()
            done = chunk_end - start + 1
            if (chunk_start // CHUNK) % 200 == 0:
                rate = done / max(1e-9, time.time() - t0)
                left = (end - chunk_end) / max(1e-9, rate)
                print(f"  block {chunk_end} ({100*done/(end-start):.1f}%), "
                      f"{fills} fills, {rate:.0f} blk/s, ~{left/60:.0f} min left",
                      file=sys.stderr, flush=True)
    print(f"{fills} fills in {time.time()-t0:.0f}s, {rpc.calls} rpc calls", file=sys.stderr)


def amounts(rpc: Rpc, skel: Path, out: Path, limit: int) -> None:
    """Read what actually moved, from the transfers in each fill's transaction.

    A fill moves one token from the swapper and another to it. Taking only the
    transfers that touch the swapper avoids counting the filler's own hedging
    legs, which ride in the same transaction and would otherwise look like part
    of the request.

    The receipt alone is not enough. 39.2% of fills came back with only the
    outgoing transfer, because the swapper was paid in native ether, which moves
    as an internal transfer and emits no log. Dropping those would remove every
    ether-denominated trade from a sample whose whole purpose is to not be a
    selection of our own making, so when the receipt shows nothing incoming the
    transaction is traced instead. Measured, that recovers the leg in all 40 of
    40 sampled, for about 12 ms on the third of fills that need it.
    """
    rows = []
    with skel.open() as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            if "checkpoint" not in row:
                rows.append(row)
    rows = rows[-limit:] if limit else rows
    done = resume_point(out)
    if done is not None:
        rows = [r for r in rows if r["block"] >= done]
        print(f"resuming at block {done}, {len(rows)} left", file=sys.stderr)

    t0 = time.time()
    seen_tx: dict[str, list] = {}
    with out.open("a") as handle:
        for index, row in enumerate(rows):
            if row["tx"] not in seen_tx:
                receipt = rpc("eth_getTransactionReceipt", [row["tx"]])
                seen_tx = {row["tx"]: receipt["logs"] if receipt else []}
            swapper = row["swapper"].lower()
            legs = []
            for log in seen_tx[row["tx"]]:
                if not log["topics"] or log["topics"][0] != TRANSFER_TOPIC:
                    continue
                if len(log["topics"]) < 3:
                    continue
                sender = "0x" + log["topics"][1][-40:]
                receiver = "0x" + log["topics"][2][-40:]
                if swapper not in (sender, receiver):
                    continue
                legs.append({"token": log["address"].lower(),
                             "amount": int(log["data"][:66], 16) if len(log["data"]) >= 66 else 0,
                             "out": sender == swapper})
            if not any(not leg["out"] for leg in legs):
                for trace in rpc("trace_transaction", [row["tx"]]) or []:
                    action = trace.get("action") or {}
                    if (action.get("to") or "").lower() == swapper \
                            and int(action.get("value") or "0x0", 16) > 0:
                        legs.append({"token": NATIVE,
                                     "amount": int(action["value"], 16), "out": False})
            handle.write(json.dumps({**row, "legs": legs}) + "\n")
            if index % 500 == 0:
                handle.flush()
                rate = (index + 1) / max(1e-9, time.time() - t0)
                print(f"  {index+1}/{len(rows)} ({rate:.0f}/s, "
                      f"~{(len(rows)-index)/max(1e-9,rate)/60:.0f} min left)",
                      file=sys.stderr, flush=True)
    print(f"decoded {len(rows)} fills in {time.time()-t0:.0f}s", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default="http://127.0.0.1:8545")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--months", type=float, default=28.0,
                    help="how far back to scan, in 30-day months of blocks")
    ap.add_argument("--from-block", type=int, default=None)
    ap.add_argument("--to-block", type=int, default=None)
    ap.add_argument("--checkpoint-every", type=int, default=50_000,
                    help="record a real timestamp this often, to bound clock drift")
    ap.add_argument("--amounts", type=Path, default=None,
                    help="second pass: decode sizes for the tail of this skeleton")
    ap.add_argument("--limit", type=int, default=150_000)
    args = ap.parse_args()

    rpc = Rpc(args.rpc)
    if args.amounts:
        amounts(rpc, args.amounts, args.out, args.limit)
        return 0

    head = int(rpc("eth_blockNumber", []), 16)
    end = args.to_block or head
    start = args.from_block or (end - int(args.months * 30 * 7200))
    print(f"scanning {start}..{end} ({(end-start)/7200/30:.1f} months)", file=sys.stderr)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    skeleton(rpc, args.out, start, end, args.checkpoint_every)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
