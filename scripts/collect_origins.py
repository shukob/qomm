#!/usr/bin/env python3
"""Where each swapper address came from, so the entity column stops being invented.

The per-entity contribution cap defends against one firm splitting its activity
across wallets. The maker side of UniswapX has that structure and it is provable
--- 45 firms, a median of 3 addresses each, two of them submitting from 35 and 38
--- but the taker side reads as 181,667 separate hands, so an entity column there
has to be recovered rather than observed.

Common funding is the standard heuristic for that, and using it here is not a
compromise. `attackers.passive_observer` already assumes an adversary who has
attributed a fraction `linkage_rho` of wallets to entities, fixed at 0.5 with
nothing behind the number. Running the heuristic *is* that adversary, and its
yield is a measurement of a parameter the study currently guesses.

The lookup is bisection, not scanning. It first looked as though this node could
not answer anything per address --- trace_filter and getLogs both cap a query at
1000 blocks and the otterscan namespace is off --- but an archive node answers
`eth_getCode`, `eth_getBalance` and `eth_getTransactionCount` at any height, and
that is enough: 25 calls locate an origin in 25.8M blocks, against the 25,786
chunked calls a scan would need. About 0.2 s per address.

Two traps, both found by checking rather than by reasoning:

*Balance is not monotone.* An address that spent everything reads zero at the
head, and bisecting on `balance > 0` silently drops it --- two of the twelve
busiest went that way. The nonce never decreases, so bisect that first: before
the first outgoing transaction an address can only have received, and balance is
genuinely monotone inside that range.

*Most "contracts" here are not contracts.* Of the 600 busiest swappers, 22.7%
carry code but 0.2% were deployed; the rest are EIP-7702 delegated keys, whose
code appears when the delegation is signed rather than when the address is
funded. They have to be treated as keys. Their delegation target is not an
entity signal either --- 100 of them point at one implementation, which is a
wallet product, not an operator.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

DELEGATION_PREFIX = "0xef0100"          # EIP-7702 designator, not a program


class Rpc:
    def __init__(self, url: str):
        self.url = url
        self.calls = 0

    def __call__(self, method: str, params: list, retries: int = 4, timeout: int = 60):
        payload = json.dumps({"jsonrpc": "2.0", "method": method,
                              "params": params, "id": 1}).encode()
        for attempt in range(retries):
            try:
                req = urllib.request.Request(
                    self.url, payload, {"Content-Type": "application/json"})
                body = json.load(urllib.request.urlopen(req, timeout=timeout))
                self.calls += 1
                return None if "error" in body else body.get("result")
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                if attempt == retries - 1:
                    raise
                time.sleep(2 ** attempt)


def bisect(pred, lo: int, hi: int):
    """Lowest block in [lo, hi] where pred holds, or None if it never does."""
    if not pred(hi):
        return None
    while lo < hi:
        mid = (lo + hi) // 2
        if pred(mid):
            hi = mid
        else:
            lo = mid + 1
    return lo


def origin(rpc: Rpc, addr: str, head: int) -> dict:
    code = rpc("eth_getCode", [addr, "latest"]) or "0x"
    deployed = code != "0x" and not code.startswith(DELEGATION_PREFIX)

    if deployed:
        block = bisect(lambda b: (rpc("eth_getCode", [addr, hex(b)]) or "0x") != "0x", 0, head)
        kind = "contract"
        if block is not None:
            for trace in rpc("trace_block", [hex(block)]) or []:
                if trace.get("type") == "create" and \
                        ((trace.get("result") or {}).get("address") or "").lower() == addr:
                    return {"address": addr, "kind": kind, "block": block,
                            "origin": ((trace.get("action") or {}).get("from") or "").lower(),
                            "evidence": "deployer"}
        return {"address": addr, "kind": kind, "block": block, "origin": None,
                "evidence": "deployer not found in the block's traces"}

    kind = "delegated key" if code.startswith(DELEGATION_PREFIX) else "key"
    # the nonce is monotone, so this bound is exact; below it the address can
    # only have received, which makes balance monotone in that range
    spent = bisect(
        lambda b: int(rpc("eth_getTransactionCount", [addr, hex(b)]) or "0x0", 16) > 0, 0, head)
    block = bisect(lambda b: int(rpc("eth_getBalance", [addr, hex(b)]) or "0x0", 16) > 0,
                   0, spent if spent is not None else head)
    if block is None:
        return {"address": addr, "kind": kind, "block": None, "origin": None,
                "evidence": "never held a balance"}
    for trace in rpc("trace_block", [hex(block)]) or []:
        action = trace.get("action") or {}
        if (action.get("to") or "").lower() == addr and int(action.get("value") or "0x0", 16) > 0:
            return {"address": addr, "kind": kind, "block": block,
                    "origin": (action.get("from") or "").lower(), "evidence": "first funding"}
    return {"address": addr, "kind": kind, "block": block, "origin": None,
            "evidence": "funding trace not found"}


def candidates(path: Path, threshold: int) -> tuple[list[str], dict]:
    counts: collections.Counter = collections.Counter()
    with path.open() as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            if "checkpoint" not in row:
                counts[row["swapper"]] += 1
    keep = [a for a, n in counts.items() if n >= threshold]
    return keep, counts


def cluster(rows: list[dict], counts: dict, hub_limit: int) -> dict:
    """Addresses sharing an origin are one entity, unless the origin is a hub.

    A funder that paid out to hundreds of these addresses is an exchange or a
    bridge; linking through it would merge unrelated people into one entity, so
    those are dropped rather than trusted. What remains is a lower bound.
    """
    by_origin = collections.defaultdict(list)
    for row in rows:
        if row.get("origin"):
            by_origin[row["origin"]].append(row["address"])
    hubs = {o for o, addrs in by_origin.items() if len(addrs) > hub_limit}

    parent: dict[str, str] = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for origin_addr, addrs in by_origin.items():
        if origin_addr in hubs:
            continue
        for other in addrs[1:]:
            ra, rb = find(addrs[0]), find(other)
            if ra != rb:
                parent[ra] = rb

    groups = collections.defaultdict(list)
    for row in rows:
        if row.get("origin"):
            groups[find(row["address"])].append(row["address"])
    multi = [v for v in groups.values() if len(v) > 1]
    sizes = sorted((len(v) for v in multi), reverse=True)
    resolved = sum(1 for r in rows if r.get("origin"))
    linked = sum(sizes)
    requests_in_multi = sum(counts.get(a, 0) for group in multi for a in group)
    return {
        "addresses": len(rows),
        "origin_resolved": resolved,
        "hub_origins_dropped": len(hubs),
        "entities": len(groups),
        "entities_with_more_than_one_wallet": len(multi),
        "wallets_in_multi_wallet_entities": linked,
        "linkage_rho_estimate": linked / max(1, resolved),
        "requests_in_multi_wallet_entities": requests_in_multi,
        "median_wallets_per_multi_entity": (sizes[len(sizes) // 2] if sizes else 0),
        "largest_entities": sizes[:15],
        "kinds": dict(collections.Counter(r["kind"] for r in rows)),
        "unresolved_reasons": dict(collections.Counter(
            r["evidence"] for r in rows if not r.get("origin"))),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default="http://127.0.0.1:8545")
    ap.add_argument("--fills", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--threshold", type=int, default=3,
                    help="skip addresses below this many requests; one request "
                         "cannot have been split across wallets by anyone")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--hub-limit", type=int, default=50)
    ap.add_argument("--cluster-only", action="store_true")
    args = ap.parse_args()

    keep, counts = candidates(args.fills, args.threshold)
    print(f"{len(counts)} swappers, {len(keep)} with at least {args.threshold} requests "
          f"({100*sum(counts[a] for a in keep)/max(1,sum(counts.values())):.1f}% of flow)",
          file=sys.stderr)

    done: dict[str, dict] = {}
    if args.out.exists():
        with args.out.open() as handle:
            for line in handle:
                if line.strip():
                    try:
                        row = json.loads(line)
                        done[row["address"]] = row
                    except json.JSONDecodeError:
                        break
        print(f"{len(done)} already resolved", file=sys.stderr)

    if not args.cluster_only:
        rpc = Rpc(args.rpc)
        head = int(rpc("eth_blockNumber", []), 16)
        todo = [a for a in keep if a not in done]
        t0 = time.time()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("a") as handle:
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                for index, row in enumerate(
                        pool.map(lambda a: origin(Rpc(args.rpc), a, head), todo)):
                    handle.write(json.dumps(row) + "\n")
                    done[row["address"]] = row
                    if index % 500 == 0:
                        handle.flush()
                        rate = (index + 1) / max(1e-9, time.time() - t0)
                        print(f"  {index+1}/{len(todo)} ({rate:.1f}/s, "
                              f"~{(len(todo)-index)/max(1e-9,rate)/60:.0f} min left)",
                              file=sys.stderr, flush=True)

    rows = [done[a] for a in keep if a in done]
    print(json.dumps(cluster(rows, counts, args.hub_limit), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
