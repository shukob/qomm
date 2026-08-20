#!/usr/bin/env python3
"""Draw every measurement from its artifact, so a reader can see the shape.

The tables in RESULTS.md and the paper are generated from the same files this
reads, so nothing here is a second source of truth --- a figure that disagrees
with a table means one of them is reading the wrong field, not that the
measurement is ambiguous.

Each figure declares which artifacts it needs and is skipped, with a note, when
they are absent. That matters because several of these come from machines not
everyone has: the MPC figures need a seven-party run, the chain figures need an
archive node. A reader with neither should still get every figure that the
repository's own data supports.

Output goes to artifacts/figures as PDF for the paper and PNG for looking at.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt                                              # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
ART = ROOT / "artifacts"
sys.path.insert(0, str(ROOT))

# One restrained palette, used the same way everywhere: the query-oblivious arm
# is always the same colour, the plain arms always another, so a reader who
# learns the first figure can read the rest without a legend.
OBLIVIOUS = "#1f4e79"
PLAIN = "#c0504d"
NEUTRAL = "#7f7f7f"
ACCENT = "#4f7942"
GRID = {"color": "#dddddd", "linewidth": 0.6}


def load(name: str):
    path = ART / name
    if not path.exists():
        return None
    text = path.read_text()
    if name.endswith(".jsonl"):
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    return json.loads(text)


def frame(ax, title: str, xlabel: str, ylabel: str) -> None:
    ax.set_title(title, fontsize=10, loc="left")
    ax.set_xlabel(xlabel, fontsize=9)
    ax.set_ylabel(ylabel, fontsize=9)
    ax.grid(True, **GRID)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.tick_params(labelsize=8)


def save(fig, stem: str, out: Path) -> str:
    out.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    for suffix in ("pdf", "png"):
        fig.savefig(out / f"{stem}.{suffix}", dpi=160, bbox_inches="tight")
    plt.close(fig)
    return stem


# --- figures ---------------------------------------------------------------

def fig_rho(out: Path):
    """The headline: only one of the two compared numbers is about the protocol."""
    data = load("rho_sweep.json")
    if not data:
        return None, "rho_sweep.json (make rho-sweep)"
    arms = [k for k in ("generated", "tape") if k in data["arms"]]
    fig, axes = plt.subplots(1, len(arms), figsize=(4.6 * len(arms), 3.4), squeeze=False)
    for ax, arm in zip(axes[0], arms):
        rows = data["arms"][arm]["rows"]
        for protocol, colour, label in (("qomm_rfq", OBLIVIOUS, "query-oblivious"),
                                        ("plain_rfq", PLAIN, "plain RFQ")):
            pts = sorted((r["linkage_rho"], r["auc_mean"])
                         for r in rows if r["protocol"] == protocol)
            if pts:
                ax.plot([p[0] for p in pts], [p[1] for p in pts], "o-",
                        color=colour, label=label, markersize=4, linewidth=1.6)
        ax.axhline(0.5, color=NEUTRAL, linestyle=":", linewidth=1)
        source = data["arms"][arm]["meta"].get("source", arm)
        frame(ax, source, "fraction of wallets the adversary can already attribute",
              "detection AUC")
        ax.set_ylim(0.45, 1.03)
        ax.legend(fontsize=8, frameon=False, loc="upper left")
    return save(fig, "rho_sweep", out), None


def fig_settlement_cost(out: Path):
    """Cost is set by the ledger's width, and the port moves the whole curve."""
    py, rs = load("defmi.json"), load("rust_bench.json")
    if not py:
        return None, "defmi.json (make defmi)"
    fig, (left, right) = plt.subplots(1, 2, figsize=(9.2, 3.4))
    scaling = py["scaling"]
    left.plot([r["bits"] for r in scaling], [r["settle_ms"] for r in scaling],
              "o-", color=PLAIN, label="Python, bit decomposition", markersize=4)
    right.plot([r["bits"] for r in scaling], [r["package_bytes"] / 1024 for r in scaling],
               "o-", color=PLAIN, label="Python", markersize=4)
    if rs:
        left.plot([r["bits"] for r in rs["scaling"]], [r["settle_ms"] for r in rs["scaling"]],
                  "s-", color=OBLIVIOUS, label="Rust, aggregated range proofs", markersize=4)
        right.plot([r["bits"] for r in rs["scaling"]],
                   [r["package_bytes"] / 1024 for r in rs["scaling"]],
                   "s-", color=OBLIVIOUS, label="Rust", markersize=4)
    frame(left, "settlement verification", "ledger balance width (bits)", "ms")
    frame(right, "wire size", "ledger balance width (bits)", "KiB")
    left.legend(fontsize=8, frameon=False)
    right.legend(fontsize=8, frameon=False)
    return save(fig, "settlement_cost", out), None


def fig_parallel(out: Path):
    """Node capacity is procurement, not design."""
    local, big = load("defmi.json"), load("defmi_host_a.json")
    if not local or "parallel" not in local:
        return None, "defmi.json with a parallel section"
    fig, ax = plt.subplots(figsize=(4.8, 3.4))
    for data, colour, label in ((local, PLAIN, "host-c"), (big, OBLIVIOUS, "host-a")):
        if not data or "parallel" not in data:
            continue
        rows = data["parallel"]
        ax.plot([r["workers"] for r in rows], [r["per_second"] for r in rows],
                "o-", color=colour, label=label, markersize=4)
        ideal = [rows[0]["per_second"] * r["workers"] for r in rows]
        ax.plot([r["workers"] for r in rows], ideal, ":", color=colour,
                linewidth=1, alpha=0.6)
    frame(ax, "settlement verification scales with cores\n(dotted: perfect scaling)",
          "worker processes", "settlements per second")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.legend(fontsize=8, frameon=False)
    return save(fig, "parallel_scaling", out), None


def fig_residency(out: Path):
    """Batching is the lever; keeping the compiler resident is the smaller half."""
    data = load("mpc_resident.json")
    if not data:
        return None, "mpc_resident.json (make mpc-resident)"
    fig, (left, right) = plt.subplots(1, 2, figsize=(9.2, 3.4))
    cold, warm = data["cold"], data["resident"]
    left.plot([r["batch"] for r in cold], [r["ms_per_quote"] for r in cold],
              "o-", color=PLAIN, label="compiler runs every time", markersize=4)
    left.plot([r["batch"] for r in warm], [r["ms_per_quote"] for r in warm],
              "s-", color=OBLIVIOUS, label="compiled circuit kept", markersize=4)
    frame(left, "cost of one quote", "requests per job", "ms per quote")
    left.set_xscale("log", base=2)
    left.set_yscale("log")
    left.legend(fontsize=8, frameon=False)

    right.plot([r["batch"] for r in warm], [r["protocol_ms_per_quote"] for r in warm],
               "s-", color=OBLIVIOUS, label="protocol", markersize=4)
    right.plot([r["batch"] for r in warm], [r["overhead_ms_per_quote"] for r in warm],
               "^-", color=NEUTRAL, label="fixed cost", markersize=4)
    frame(right, "where the time goes once the circuit is kept",
          "requests per job", "ms per quote")
    right.set_xscale("log", base=2)
    right.legend(fontsize=8, frameon=False)
    return save(fig, "mpc_residency", out), None


def _symbol(source: str) -> str:
    match = re.search(r"bybit:([A-Z0-9]+)", source or "")
    return match.group(1) if match else (source or "?")


def fig_real_market(out: Path):
    """Across 88x in liquidity, one arm does not move and the other barely does."""
    data = load("sim_matrix_bybit.json")
    if not data:
        return None, "sim_matrix_bybit.json (make sim-real)"
    rows = [r for r in (data.get("aggregate") or []) if "source" in r]
    raw = data.get("rows") or []
    rate = {}
    for r in raw:
        tape = r.get("tape") or {}
        if tape.get("source"):
            rate[_symbol(tape["source"])] = tape.get("arrival_per_s", 0)

    def value(row, key):
        v = row.get(key)
        return v.get("mean") if isinstance(v, dict) else v

    fig, (left, right) = plt.subplots(1, 2, figsize=(9.4, 3.4))
    for protocol, colour, label in (("qomm_rfq", OBLIVIOUS, "query-oblivious"),
                                    ("plain_rfq", PLAIN, "plain RFQ")):
        pts = []
        for row in rows:
            if row["protocol"] != protocol or row["disclosure"] != "A_none" \
                    or row["layer"] != "replay":
                continue
            auc = value(row, "A1_passive_observer.auc")
            symbol = _symbol(row["source"])
            if auc is not None and symbol in rate:
                pts.append((rate[symbol], auc))
        pts.sort()
        if pts:
            left.plot([p[0] for p in pts], [p[1] for p in pts], "o",
                      color=colour, label=label, markersize=5)
    left.axhline(0.5, color=NEUTRAL, linestyle=":", linewidth=1)
    frame(left, "detection across eight real symbols", "trades per second", "detection AUC")
    left.set_xscale("log")
    left.set_ylim(0.45, 0.85)
    left.legend(fontsize=8, frameon=False)

    for disclosure, colour, label in (("C_dp", OBLIVIOUS, "differentially private"),
                                      ("B_threshold", PLAIN, "threshold")):
        pts = []
        for row in rows:
            if row["protocol"] != "plain_rfq" or row["disclosure"] != disclosure \
                    or row["layer"] != "reactive":
                continue
            symbol = _symbol(row["source"])
            suppression = value(row, "suppression_rate")
            if suppression is not None and symbol in rate:
                pts.append((rate[symbol], suppression))
        pts.sort()
        if pts:
            right.plot([p[0] for p in pts], [p[1] for p in pts], "o-",
                       color=colour, label=label, markersize=5)
    frame(right, "how often disclosure is withheld", "trades per second",
          "fraction of windows suppressed")
    right.set_xscale("log")
    right.set_ylim(-0.05, 1.05)
    right.legend(fontsize=8, frameon=False)
    return save(fig, "real_market", out), None


def fig_relay(out: Path):
    """Relay hops with clocks that do not agree."""
    across, within = load("transport.json"), load("transport_colocated.json")
    if not across:
        return None, "transport.json (make transport)"
    fig, ax = plt.subplots(figsize=(4.8, 3.4))
    for data, colour, label in ((within, OBLIVIOUS, "within one site (0.43 ms)"),
                                (across, PLAIN, "between sites (8.7 ms)")):
        if not data:
            continue
        rows = sorted(data["by_hops"], key=lambda r: r["hops"])
        ax.plot([r["hops"] for r in rows],
                [r.get("slot_wall_median_ms", 0) for r in rows],
                "o-", color=colour, label=label, markersize=4)
    frame(ax, "each relay keeps its own clock", "relay hops", "ms per slot")
    ax.legend(fontsize=8, frameon=False)
    return save(fig, "relay_hops", out), None


def fig_wasm(out: Path):
    """The verifier on the machine a chain would run it on."""
    native, wasm = load("wasm_native.json"), load("wasm_wasm32.json")
    if not native or not wasm:
        return None, "wasm_native.json and wasm_wasm32.json (make wasm-bench)"
    fig, ax = plt.subplots(figsize=(4.8, 3.4))
    bits = [r["bits"] for r in native["scaling"]]
    width = 0.35
    positions = range(len(bits))
    ax.bar([p - width / 2 for p in positions],
           [r["settle_ms"] for r in native["scaling"]], width,
           color=OBLIVIOUS, label="native")
    ax.bar([p + width / 2 for p in positions],
           [r["settle_ms"] for r in wasm["scaling"]], width,
           color=PLAIN, label="WebAssembly")
    ax.set_xticks(list(positions))
    ax.set_xticklabels([f"{b} bit" for b in bits])
    frame(ax, "settlement verification, same source", "", "ms")
    ax.legend(fontsize=8, frameon=False)
    return save(fig, "wasm_vs_native", out), None


def fig_notes(out: Path):
    """What an anonymity set costs, and who pays."""
    data = load("defmi.json")
    if not data or "notes" not in data:
        return None, "defmi.json with a notes section"
    rings = data["notes"]["rings"]
    fig, ax = plt.subplots(figsize=(4.8, 3.4))
    ax.plot([r["ring"] for r in rings], [r["build_ms"] for r in rings], "o-",
            color=PLAIN, label="payer proves", markersize=4)
    ax.plot([r["ring"] for r in rings], [r["check_ms"] for r in rings], "s-",
            color=OBLIVIOUS, label="node verifies", markersize=4)
    frame(ax, "the anonymity set is bounded by the payer, not the node",
          "candidates the spend hides among", "ms")
    ax.set_xscale("log", base=2)
    ax.legend(fontsize=8, frameon=False)
    return save(fig, "anonymity_set", out), None


def fig_placement(out: Path):
    """One distant node costs most of what seven do."""
    data = load("placement.json")
    if not data:
        return None, "placement.json (make placement, needs seven parties)"
    rows = data["rows"]
    fig, ax = plt.subplots(figsize=(5.2, 3.4))
    colours = {"all near": ACCENT, "one far": PLAIN,
               "one near": NEUTRAL, "all far": NEUTRAL}
    ax.bar([r["placement"] for r in rows], [r["wall_median_s"] for r in rows],
           color=[colours.get(r["placement"], NEUTRAL) for r in rows], width=0.6)
    frame(ax, f"node placement ({data['near_ms']:.0f} ms near, "
              f"{data['far_ms']:.0f} ms far)", "", "seconds per quote")
    ax.tick_params(axis="x", labelrotation=15)
    return save(fig, "node_placement", out), None


def fig_state_audit(out: Path):
    """The per-fill audit does not grow with the chain behind it."""
    data = load("state_audit.json")
    if not data:
        return None, "state_audit.json (make state-audit)"
    chains = data["chains"]
    fig, ax = plt.subplots(figsize=(4.8, 3.4))
    ax.plot([r["steps"] for r in chains], [r["prove_ms_per_step"] for r in chains],
            "o-", color=PLAIN, label="maker proves", markersize=4)
    ax.plot([r["steps"] for r in chains], [r["verify_ms_per_step"] for r in chains],
            "s-", color=OBLIVIOUS, label="venue verifies", markersize=4)
    frame(ax, "auditing one inventory update", "fills already in the chain",
          "ms per fill")
    ax.set_ylim(0, max(r["verify_ms_per_step"] for r in chains) * 1.4)
    ax.legend(fontsize=8, frameon=False)
    return save(fig, "state_audit", out), None


def fig_dp_effect(out: Path):
    """Paired differences against publishing nothing, before and after the fix."""
    data = load("dp_effect.json")
    if not data:
        return None, "dp_effect.json (make dp-effect)"
    arms = [k for k in ("generated", "tape") if k in data["arms"]]
    fig, axes = plt.subplots(1, len(arms), figsize=(4.6 * len(arms), 3.4), squeeze=False)
    for ax, arm in zip(axes[0], arms):
        paired = data["arms"][arm]["paired_against_no_disclosure"]
        labels, means, errors, colours = [], [], [], []
        for kind, colour in (("dp_uncorrected", PLAIN), ("dp_corrected", OBLIVIOUS)):
            stat = paired[kind]["fill_rate"]
            if stat["mean"] is None:
                continue
            labels.append("as published" if kind == "dp_uncorrected" else "corrected")
            means.append(stat["mean"])
            errors.append(stat["half_width"])
            colours.append(colour)
        ax.bar(labels, means, yerr=errors, color=colours, width=0.5, capsize=6)
        ax.axhline(0, color=NEUTRAL, linewidth=1)
        source = data["arms"][arm]["meta"].get("source", arm)
        frame(ax, f"fill rate against publishing nothing\n{source}", "", "difference")
    return save(fig, "dp_effect", out), None


FIGURES = (fig_rho, fig_settlement_cost, fig_parallel, fig_residency,
           fig_real_market, fig_relay, fig_wasm, fig_notes, fig_placement,
           fig_state_audit, fig_dp_effect)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ART / "figures")
    args = ap.parse_args()

    drawn, skipped = [], []
    for figure in FIGURES:
        name, missing = figure(args.out)
        if name:
            drawn.append(name)
            print(f"  drew {name}")
        else:
            skipped.append((figure.__name__, missing))
    if skipped:
        print("\nskipped, because their measurements are not in this checkout:")
        for name, missing in skipped:
            print(f"  {name}: needs {missing}")
    print(f"\n{len(drawn)} figure(s) in {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
