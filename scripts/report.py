#!/usr/bin/env python3
"""Turn the measurement artifacts into the tables used in RESULTS.md.

Also checks the predictions written in THEORY.md before any measurement was
taken, and says plainly which ones survived.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


def load_sweep(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return [r for r in rows if r.get("verified")]


def sweep_table(rows: list[dict], mode: str, disclose: str = "none") -> str:
    keep = [r for r in rows if r["mode"] == mode and r["disclose"] == disclose]
    delays = sorted({r["delay_ms"] for r in keep})
    mms = sorted({r["n_mm"] for r in keep})
    header = "| M | rounds | sent (MB/party) | " + " | ".join(f"{d:g}ms" for d in delays) + " |"
    sep = "|---:" * (3 + len(delays)) + "|"
    lines = [header, sep]
    for n_mm in mms:
        cells = []
        rounds = mb = None
        for delay in delays:
            match = [r for r in keep if r["n_mm"] == n_mm and r["delay_ms"] == delay]
            if not match:
                cells.append("-")
                continue
            row = match[0]
            rounds = rounds or row.get("measured_rounds")
            mb = mb or row.get("measured_mb")
            cells.append(f"{row['wall_median']:.3f}")
        lines.append(f"| {n_mm} | {rounds} | {mb} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def round_scaling(rows: list[dict], mode: str) -> dict:
    """Fit rounds = a + b*log2(M) and rounds = a + b*M; report which fits."""
    keep = {r["n_mm"]: r["measured_rounds"] for r in rows
            if r["mode"] == mode and r["disclose"] == "none" and r["delay_ms"] == 0}
    if len(keep) < 3:
        return {}
    xs_log = [math.log2(m) for m in sorted(keep)]
    xs_lin = [float(m) for m in sorted(keep)]
    ys = [float(keep[m]) for m in sorted(keep)]

    def fit(xs: list[float], ys: list[float]) -> tuple[float, float, float]:
        n = len(xs)
        mx, my = sum(xs) / n, sum(ys) / n
        sxx = sum((x - mx) ** 2 for x in xs)
        sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
        b = sxy / sxx if sxx else 0.0
        a = my - b * mx
        ss_res = sum((y - (a + b * x)) ** 2 for x, y in zip(xs, ys))
        ss_tot = sum((y - my) ** 2 for y in ys)
        return a, b, (1 - ss_res / ss_tot if ss_tot else 0.0)

    a_log, b_log, r2_log = fit(xs_log, ys)
    a_lin, b_lin, r2_lin = fit(xs_lin, ys)
    return {
        "measured": {m: keep[m] for m in sorted(keep)},
        "log2_fit": {"intercept": a_log, "slope": b_log, "r2": r2_log},
        "linear_fit": {"intercept": a_lin, "slope": b_lin, "r2": r2_lin},
        "verdict": "logarithmic" if r2_log > r2_lin else "linear",
    }


def check_predictions(rows: list[dict], clob: dict) -> list[dict]:
    """Score THEORY.md's pre-registered predictions against what was measured."""
    def pick(mode: str, n_mm: int, delay: float, disclose: str = "none") -> dict | None:
        hits = [r for r in rows if r["mode"] == mode and r["n_mm"] == n_mm
                and r["delay_ms"] == delay and r["disclose"] == disclose]
        return hits[0] if hits else None

    out: list[dict] = []

    # A: round count must grow far slower than M
    small, large = pick("rfq", 4, 0), pick("rfq", 64, 0)
    if small and large:
        ratio = large["measured_rounds"] / small["measured_rounds"]
        out.append({
            "id": "A", "claim": "the round count grows only logarithmically in M",
            "evidence": f"M 4->64 (16x) takes rounds {small['measured_rounds']}->"
                        f"{large['measured_rounds']} = {ratio:.2f}x",
            "verdict": "PASS" if ratio < 4 else "FAIL",
            "note": "linear would be 16x; how well the log model actually fits is judged separately by R^2",
        })

    # B: at equal delay the quote circuit beats the CLOB circuit by an order of magnitude
    if clob:
        ratios = []
        for delay, base in clob.items():
            row = pick("rfq", 16, float(delay))
            if row:
                ratios.append(base["wall_median"] / row["wall_median"])
        if ratios:
            out.append({
                "id": "B", "claim": "at equal delay, an order of magnitude faster than the existing CLOB circuit",
                "evidence": "ratio " + ", ".join(f"{r:.1f}x" for r in ratios),
                "verdict": "PASS" if min(ratios) >= 10 else "PARTIAL",
                "note": "controlled: same host, same protocol, same threshold",
            })

    # C: even so, wide-area round trips keep the answer in seconds
    wide = pick("rfq", 16, 15)
    if wide:
        out.append({
            "id": "C", "claim": "over a wide area the communication floor dominates and it stays in seconds",
            "evidence": f"15 ms one way (30 ms RTT), M=16, RFQ: median {wide['wall_median']:.3f} s "
                        f"({wide['measured_rounds']} rounds)",
            "verdict": "PASS" if wide["wall_median"] > 0.5 else "FAIL",
            "note": "does not reach an immediate answer (<200 ms); an order of magnitude fewer rounds would still not",
        })

    # D/E: hiding the direction is essentially free, two-sided output is not 2x
    rfq16, rfm16 = pick("rfq", 16, 1), pick("rfm", 16, 1)
    if rfq16 and rfm16:
        out.append({
            "id": "D", "claim": "hiding the side costs essentially nothing (the RFQ circuit is the RFM circuit)",
            "evidence": f"rounds RFQ {rfq16['measured_rounds']} / RFM {rfm16['measured_rounds']}",
            "verdict": "PASS" if abs(rfq16["measured_rounds"] - rfm16["measured_rounds"]) <= 2
                       else "FAIL",
            "note": "an unencrypted RFM hides the side too; that must not be counted as an effect of the MPC",
        })
        ratios = []
        for delay in sorted({r["delay_ms"] for r in rows}):
            a, b = pick("rfq", 64, delay), pick("rfm", 64, delay)
            if a and b:
                ratios.append(b["wall_median"] / a["wall_median"])
        if ratios:
            out.append({
                "id": "E", "claim": "RFM answers within 1.0 to 1.3x the time RFQ takes",
                "evidence": "ratio at M=64 " + ", ".join(f"{r:.2f}" for r in ratios),
                "verdict": "PASS" if max(ratios) <= 1.3 else "FAIL",
                "note": "two trees instead of one, but the depth of a layer is unchanged",
            })

    # F: RFS was predicted to cost k times a single quote
    rfs16, rfq16d = pick("rfs", 16, 15), pick("rfq", 16, 15)
    if rfs16 and rfq16d:
        latency_ratio = rfs16["wall_median"] / rfq16d["wall_median"]
        round_ratio = rfs16["measured_rounds"] / rfq16d["measured_rounds"]
        out.append({
            "id": "F", "claim": "RFS (k=5) takes about five times as long in total as RFQ",
            "evidence": f"round ratio {round_ratio:.2f}, wall-clock ratio {latency_ratio:.2f}",
            "verdict": "PASS" if 4.0 <= latency_ratio <= 6.0 else "REFUTED",
            "note": "rounds are about k times as predicted, but the wall clock is less than that: "
                    "repeating the same circuit amortises preprocessing and start-up",
        })

    # G: threshold disclosure adds a constant number of rounds and under 10% time
    increments, overheads = [], []
    for n_mm in sorted({r["n_mm"] for r in rows}):
        a, b = pick("rfq", n_mm, 1, "none"), pick("rfq", n_mm, 1, "threshold")
        if a and b:
            increments.append(b["measured_rounds"] - a["measured_rounds"])
            overheads.append(b["wall_median"] / a["wall_median"] - 1)
    if increments:
        out.append({
            "id": "G", "claim": "adding threshold disclosure costs a constant number of rounds and under +10% in time",
            "evidence": f"round increments {increments}, time increments "
                        + ", ".join(f"{o * 100:+.1f}%" for o in overheads),
            "verdict": "PARTIAL" if max(overheads) > 0.10 else "PASS",
            "note": "the round increment barely depends on M; the time increment exceeds 10% at large M "
                    "because of the extra traffic",
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifacts", type=Path, default=Path("artifacts"))
    ap.add_argument("--sweep", default="qomm_sweep_clean.jsonl")
    ap.add_argument("--clob-prefix", default="clob_baseline_clean_d")
    args = ap.parse_args()

    sweep_path = args.artifacts / args.sweep
    if not sweep_path.exists():
        sweep_path = args.artifacts / "qomm_sweep.jsonl"
    rows = load_sweep(sweep_path)
    print(f"# source: {sweep_path.name}, {len(rows)} verified runs\n")

    clob = {}
    for delay in (0, 1, 5, 15):
        for prefix in (args.clob_prefix, "clob_baseline_d"):
            path = args.artifacts / f"{prefix}{delay}.json"
            if path.exists():
                clob[delay] = json.loads(path.read_text())
                break

    print("## MPC quote latency, 7 parties, malicious Shamir (N=7, T=2)\n")
    for mode in ("rfq", "rfm", "rfs"):
        if not any(r["mode"] == mode for r in rows):
            continue
        print(f"### {mode.upper()}\n")
        print(sweep_table(rows, mode))
        print()

    if any(r["disclose"] == "threshold" for r in rows):
        print("### RFQ + threshold disclosure (arm B)\n")
        print(sweep_table(rows, "rfq", "threshold"))
        print()

    if clob:
        print("## Same-host control: existing 9-order CLOB circuit\n")
        print("| one-way delay | rounds | median [s] | sent (MB/party) |")
        print("|---:|---:|---:|---:|")
        for delay in sorted(clob):
            row = clob[delay]
            print(f"| {delay} ms | {row['measured_rounds']} | {row['wall_median']:.3f} | {row['measured_mb']} |")
        print()

        print("## Speed-up over the CLOB circuit at equal delay (M=16, RFQ)\n")
        print("| one-way delay | CLOB [s] | QOMM [s] | ratio |")
        print("|---:|---:|---:|---:|")
        for delay in sorted(clob):
            match = [r for r in rows if r["mode"] == "rfq" and r["n_mm"] == 16
                     and r["disclose"] == "none" and r["delay_ms"] == delay]
            if not match:
                continue
            qomm = match[0]["wall_median"]
            base = clob[delay]["wall_median"]
            print(f"| {delay} ms | {base:.3f} | {qomm:.3f} | {base / qomm:.1f}x |")
        print()

    cross = args.artifacts / "host-b" / "host_b_sweep.jsonl"
    if cross.exists():
        other = load_sweep(cross)
        print("## Reproduced on a second host (circuit cost does not depend on the hardware)\n")
        print("| M | one-way delay | rounds (host-a / host-b) | MB sent (host-a / host-b) | "
              "median [s] host-a | median [s] host-b |")
        print("|---:|---:|---|---|---:|---:|")
        for row in other:
            match = [r for r in rows if r["mode"] == row["mode"] and r["n_mm"] == row["n_mm"]
                     and r["delay_ms"] == row["delay_ms"] and r["disclose"] == row["disclose"]]
            if not match:
                continue
            base = match[0]
            same_rounds = base["measured_rounds"] == row["measured_rounds"]
            same_bytes = base["measured_mb"] == row["measured_mb"]
            print(f"| {row['n_mm']} | {row['delay_ms']:g} ms | "
                  f"{base['measured_rounds']} / {row['measured_rounds']}"
                  f"{'' if same_rounds else ' <- differs'} | "
                  f"{base['measured_mb']} / {row['measured_mb']}"
                  f"{'' if same_bytes else ' <- differs'} | "
                  f"{base['wall_median']:.3f} | {row['wall_median']:.3f} |")
        print()

    print("## Verdict on the preregistered predictions\n")
    print("| # | prediction | measured | verdict |")
    print("|---|---|---|---|")
    for check in check_predictions(rows, clob):
        print(f"| {check['id']} | {check['claim']} | {check['evidence']} | **{check['verdict']}** |")
    print()
    for check in check_predictions(rows, clob):
        print(f"- **{check['id']}**: {check['note']}")
    print()

    print("## Round-count scaling in M\n")
    for mode in ("rfq", "rfm", "rfs"):
        fit = round_scaling(rows, mode)
        if not fit:
            continue
        print(f"- **{mode.upper()}**: {fit['measured']}")
        print(f"  - log2 fit R^2 = {fit['log2_fit']['r2']:.4f} "
              f"(slope {fit['log2_fit']['slope']:.1f} rounds per doubling)")
        print(f"  - linear fit R^2 = {fit['linear_fit']['r2']:.4f}")
        print(f"  - verdict: **{fit['verdict']}**")
    print()

    print("## Threshold disclosure overhead (arm B vs arm A)\n")
    print("| M | A rounds | B rounds | A [s] @1ms | B [s] @1ms | increment |")
    print("|---:|---:|---:|---:|---:|---:|")
    for n_mm in sorted({r["n_mm"] for r in rows}):
        a = [r for r in rows if r["mode"] == "rfq" and r["n_mm"] == n_mm
             and r["disclose"] == "none" and r["delay_ms"] == 1]
        b = [r for r in rows if r["mode"] == "rfq" and r["n_mm"] == n_mm
             and r["disclose"] == "threshold" and r["delay_ms"] == 1]
        if not a or not b:
            continue
        ratio = b[0]["wall_median"] / a[0]["wall_median"] - 1
        print(f"| {n_mm} | {a[0]['measured_rounds']} | {b[0]['measured_rounds']} | "
              f"{a[0]['wall_median']:.3f} | {b[0]['wall_median']:.3f} | {ratio * 100:+.1f}% |")
    print()

    sim_path = args.artifacts / "sim_matrix.json"
    if sim_path.exists():
        sim = json.loads(sim_path.read_text())
        print(f"## Phase-3 comparison ({sim['config']['seeds']} seeds, "
              f"{sim['config']['steps'] * 50 / 1000 / 60:.0f} minutes of simulated trading each)\n")
        _print_sim(sim)

    audit_path = args.artifacts / "dp_audit.json"
    if audit_path.exists():
        audit = json.loads(audit_path.read_text())
        print("## Entity-level DP audit (two-world membership game)\n")
        print("| declared eps/window | audit cells | measured eps lower bound (max) | violations |")
        print("|---:|---:|---:|---:|")
        for bucket in audit["by_epsilon"]:
            print(f"| {bucket['declared_epsilon']} | {bucket['cells']} | "
                  f"{bucket['max_empirical_epsilon']:.3f} | {bucket['violations']} |")
        print()
    return 0


def _fmt(cell: dict | None, digits: int = 3) -> str:
    if not cell:
        return "-"
    return f"{cell['mean']:.{digits}f} ± {cell['ci95']:.{digits}f}"


def _print_sim(sim: dict) -> None:
    agg = sim["aggregate"]
    eps_ref = sim["config"]["epsilons"][0]

    print("### Privacy (layer 1, replay experiment, eps=1.0)\n")
    print("| arm | disclosure | AUC on unsettled requests | side guessed | size band guessed | "
          "per-maker inventory correlation | total inventory correlation | informed-or-not AUC |")
    print("|---|---|---:|---:|---:|---:|---:|---:|")
    for row in agg:
        if row["layer"] != "replay":
            continue
        if row["disclosure"] == "C_dp" and row["epsilon_per_window"] != 1.0:
            continue
        print(f"| {row['protocol']} | {row['disclosure']} | "
              f"{_fmt(row.get('A1_passive_observer.auc'))} | "
              f"{_fmt(row.get('A1b_pretrade_attributes.direction_accuracy'))} | "
              f"{_fmt(row.get('A1b_pretrade_attributes.size_bucket_accuracy'))} | "
              f"{_fmt(row.get('A3_probing_entity.own_inventory_corr_from_per_mm_quotes'))} | "
              f"{_fmt(row.get('A3_probing_entity.net_inventory_corr_from_best_quote'))} | "
              f"{_fmt(row.get('A5_external_info.auc'))} |")
    print()

    for layer in ("replay", "reactive"):
        print(f"### Economics (layer {'1, replay' if layer == 'replay' else '2, reactive'} experiment, qomm_rfq)\n")
        print("| disclosure | eps/window | fill rate | user cost [tick] | maker P&L per fill | "
              "1 s markout | disclosure halt rate | eps spent | count error MAE |")
        print("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
        for row in agg:
            if row["layer"] != layer or row["protocol"] != "qomm_rfq":
                continue
            print(f"| {row['disclosure']} | {row['epsilon_per_window']} | "
                  f"{_fmt(row.get('fill_rate'))} | {_fmt(row.get('user_cost_mean_ticks'), 2)} | "
                  f"{_fmt(row.get('mm_pnl_per_fill'), 1)} | "
                  f"{_fmt(row.get('mm_markout_1s_mean'), 2)} | "
                  f"{_fmt(row.get('suppression_rate'), 2)} | "
                  f"{_fmt(row.get('epsilon_spent_max'), 1)} | "
                  f"{_fmt(row.get('release_requests_mae'), 1)} |")
        print()

    print("### Power: the smallest difference this many trials can detect\n")
    print("From the observed variance, the smallest difference a two-group comparison needs at 5% significance and 80% power.")
    print("A smaller difference than this is not 'no difference' but 'undecidable at this number of trials'.\n")
    print("| metric | mean (arm A) | standard deviation | n | minimum detectable difference | as a fraction of the mean |")
    print("|---|---:|---:|---:|---:|---:|")
    base_rows = [r for r in agg if r["layer"] == "reactive"
                 and r["protocol"] == "qomm_rfq" and r["disclosure"] == "A_none"]
    if base_rows:
        base = base_rows[0]
        for field, label, digits in (
            ("fill_rate", "fill rate", 4),
            ("user_cost_mean_ticks", "user cost [tick]", 2),
            ("mm_pnl_per_fill", "maker P&L per fill", 1),
            ("mm_markout_1s_mean", "1 s markout", 2),
        ):
            cell = base.get(field)
            if not cell or cell["n"] < 2:
                continue
            sd = cell["ci95"] * math.sqrt(cell["n"]) / 1.96
            mde = 2.80 * sd * math.sqrt(2.0 / cell["n"])
            share = mde / abs(cell["mean"]) if cell["mean"] else float("nan")
            print(f"| {label} | {cell['mean']:.{digits}f} | {sd:.{digits}f} | {cell['n']} | "
                  f"{mde:.{digits}f} | {share * 100:.0f}% |")
    print()

    print("### The cost of probing (how many probes are needed)\n")
    print("| arm | probes to reach correlation 0.8 (total inventory) | same (per-maker inventory) |")
    print("|---|---:|---:|")
    seen = set()
    for row in agg:
        if row["layer"] != "replay" or row["disclosure"] != "A_none":
            continue
        if row["protocol"] in seen:
            continue
        seen.add(row["protocol"])
        print(f"| {row['protocol']} | "
              f"{_fmt(row.get('A4_colluding_wallets.probes_needed_net_corr_0.8'), 1)} | "
              f"{_fmt(row.get('A4_colluding_wallets.probes_needed_per_mm_corr_0.8'), 1)} |")
    print()


if __name__ == "__main__":
    raise SystemExit(main())
