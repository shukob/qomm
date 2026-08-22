"""The other engine: the round is run in MP-SPDZ rather than described.

The demo's own share layer is real about the part it models and silent about
the part it does not --- the tournament is in the clear there. This engine has
no such gap: the whole circuit, comparisons included, is compiled and executed
by seven or nine party processes, and the price shown in the browser is the one
that came out of `QOMM_MASKED_KEY` in a party's log. It is checked against the
cleartext reference on every round, and a round that does not match is reported
as not matching rather than smoothed over.

What it costs is the reason it is not the default. A round is a few hundred
milliseconds of process start-up and protocol against the couple of
milliseconds the other engine takes, it needs a built MP-SPDZ with certificates
for the party count in use, and it will not run on a laptop somebody has just
been handed. The badge in the corner of every page says which engine produced
the number on screen, always, in both directions.

**The misbehaviour switches reach it when the build can carry them.** With
`atlas-party.x` and the robust patch, `--options robust` and
`QOMM_CORRUPT_PLAYER` make the named parties send a wrong share of every masked
product, the others correct it, and the log names who --- so a node seat set to
lie in the browser corrupts a real party in a real protocol. It needs `n >= 4T+1`
and a patched build; without either, the switch is stopped with the reason
rather than left looking connected, which is what `robust_reason` carries.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.run_qomm import MPSpdzRun, unpack_key, verify   # noqa: E402
from scripts.serve_qomm import DEFAULTS, SHAPE, generate     # noqa: E402

from .model import FIELDS, Outcome, Quote, evaluate          # noqa: E402


class MpcEngine:
    """One compiled circuit per shape, then one party run per round."""

    name = "mpc"
    note = "MP-SPDZ, whole circuit"

    def __init__(self, root: str | None, n_parties: int = 7, threshold: int = 2,
                 n_makers: int = 8, n_assets: int = 3, bit_length: int = 63,
                 binary: str | None = None,
                 ref_table: list[int] | None = None):
        # The robust build if there is one and the party count can carry it,
        # because that is the build where a node seat's switch means something.
        # Choosing it here rather than asking the caller keeps the one condition
        # --- n >= 4T+1 --- next to the reason for it.
        binary = binary or self._pick(root, n_parties, threshold)
        self.root = Path(root or os.environ.get(
            "MP_SPDZ_ROOT", str(Path.home() / "work/qomm/MP-SPDZ")))
        if not (self.root / binary).exists():
            raise SystemExit(
                f"no {binary} under {self.root}. Build MP-SPDZ, or point "
                f"--mp-spdz-root at a tree that has it, or leave the engine at "
                f"sim --- which needs nothing and says so on every page.")
        self.n_parties = n_parties
        self.threshold = threshold
        self.n_makers = n_makers
        self.n_assets = n_assets
        self.bit_length = bit_length
        # The room's own markets, so the number in the browser is a price in
        # the market it is labelled with. Without this the circuit prices
        # against a table spread 5000 apart, and the label would be a lie.
        self.ref_table = list(ref_table) if ref_table else None
        self.binary = binary
        self.robust = binary.startswith("atlas") and n_parties >= 4 * threshold + 1
        self.robust_reason = self._why_not(root, n_parties, threshold)
        self.workdir = Path(tempfile.mkdtemp(prefix="qomm-demo-mpc-"))
        self.run: MPSpdzRun | None = None
        self.source: Path | None = None
        self.compile_ms = 0.0
        self.served = 0
        self.note = (f"MP-SPDZ {binary.split('-party')[0]}, n={n_parties}, "
                     f"T={threshold}" + (", robust" if self.robust else ""))

    @staticmethod
    def held(inputs: Path, how_many: int = 6) -> dict[int, list[str]]:
        """The first few values of each party's own input file, as they are."""
        out: dict[int, list[str]] = {}
        for path in sorted(inputs.glob("Input-P*-0")):
            index = int(path.name.split("-")[1][1:])
            values = path.read_text(encoding="utf-8").split()[:how_many]
            out[index] = [f"{int(v) & ((1 << 72) - 1):018x}" for v in values]
        return out

    @staticmethod
    def _pick(root, n_parties: int, threshold: int) -> str:
        """The robust build when it is there and the parties can carry it."""
        base = Path(root or os.environ.get(
            "MP_SPDZ_ROOT", str(Path.home() / "work/qomm/MP-SPDZ")))
        if (base / "atlas-party.x").exists() and n_parties >= 4 * threshold + 1:
            return "atlas-party.x"
        return "malicious-shamir-party.x"

    @staticmethod
    def _why_not(root, n_parties: int, threshold: int) -> str:
        """Why a node seat's switch will not reach the engine, when it will not."""
        base = Path(root or os.environ.get(
            "MP_SPDZ_ROOT", str(Path.home() / "work/qomm/MP-SPDZ")))
        if not (base / "atlas-party.x").exists():
            return ("no atlas-party.x under the MP-SPDZ tree. Corrupting a real "
                    "party needs the robust build --- `--options robust` and "
                    "QOMM_CORRUPT_PLAYER --- and this tree does not have it.")
        if n_parties < 4 * threshold + 1:
            return (f"n = {n_parties} at T = {threshold} is below n >= 4T+1, so a "
                    f"wrong share in a multiplication is detected and not "
                    f"corrected. Robust ATLAS refuses to start rather than "
                    f"pretending; run with {4 * threshold + 1} nodes.")
        return ""

    def _request(self, request, policies=None) -> dict:
        filled = dict(DEFAULTS)
        filled.update({
            "n_mm": self.n_makers, "n_parties": self.n_parties,
            "threshold": self.threshold, "mode": "rfq",
            "n_assets": self.n_assets, "bit_length": self.bit_length,
            "ref_table": self.ref_table,
            "user_asset": request.asset, "user_qty": request.qty,
            "user_dir": request.direction, "is_real": request.is_real,
        })
        if policies is not None:
            filled["policies"] = [dict(zip(FIELDS, p.as_fields()))
                                  for p in policies]
        return filled

    def prepare(self, request, policies) -> None:
        """Compile once. The shape does not depend on any policy or any order."""
        import time

        if self.run is not None:
            return
        payload = self._request(request, policies)
        source, _, _ = generate(payload, self.workdir / "shape")
        self.source = source
        self.run = MPSpdzRun(self.root, f"qomm_demo_{os.getpid()}",
                             self.n_parties, self.threshold, binary=self.binary)
        if self.robust:
            self.run.extra_args += ["--options", "robust"]
        started = time.perf_counter()
        self.run.install(source, self.workdir / "shape" / "inputs")
        self.run.compile()
        self.compile_ms = (time.perf_counter() - started) * 1e3

    def quote(self, request, policies, reference_prices, now_t: int,
              corrupt: list | None = None):
        """One round in the engine. Returns the outcome and what it cost.

        `corrupt` is the node seats that chose to lie during a multiplication.
        They are passed to the parties in the environment, so the same value
        reaches all of them and exactly the named ones misbehave.
        """
        self.prepare(request, policies)
        payload = self._request(request, policies)
        _, inputs, reference = generate(payload, self.workdir / "live",
                                        inputs_only=True)
        # What a node holds under this engine is not a story the demo tells:
        # it is the party file the process is about to read.
        held = self.held(inputs)
        self.run.install(self.source, inputs)
        before = os.environ.get("QOMM_CORRUPT_PLAYER")
        if self.robust and corrupt:
            os.environ["QOMM_CORRUPT_PLAYER"] = ",".join(str(c) for c in corrupt)
        try:
            result = self.run.execute(0.0)
        finally:
            if before is None:
                os.environ.pop("QOMM_CORRUPT_PLAYER", None)
            else:
                os.environ["QOMM_CORRUPT_PLAYER"] = before
        # who the decoder named, from the log the parties actually wrote
        named = sorted({int(m) for m in re.findall(
            r"ROBUST_ATLAS_CORRECTED player (\d+)", result.get("log", ""))})
        stats = {"named": named, "robust": self.robust,
                 "protocol_ms": (result.get("party0_seconds") or 0.0) * 1e3,
                 "wall_ms": result["wall_seconds"] * 1e3,
                 "rounds": result.get("party0_rounds"),
                 "mb": result.get("party0_mb"),
                 "compiled_once_ms": round(self.compile_ms, 1)}
        if not result["ok"]:
            return None, False, "a party failed", stats
        ok, detail = verify("rfq", result["log"], reference)
        self.served += 1

        # The price on screen comes out of the log, not out of the reference:
        # showing the reference and calling it the engine's answer would make a
        # mismatch invisible, which is the one thing this engine is for.
        found = re.search(r"^QOMM_MASKED_KEY=(-?\d+)", result["log"], re.M)
        outcome = Outcome(eligible=reference["eligible_count"])
        outcome.quotes = [Quote(maker=q["mm"], ask=q["ask"], bid=q["bid"],
                                eligible=q["eligible"]) for q in reference["quotes"]]
        if found and not reference.get("no_eligible_maker"):
            cost, maker = unpack_key(int(found.group(1)) - reference["mask"],
                                     reference["padded_mm"])
            outcome.cost, outcome.winner = cost, maker
            outcome.price = -cost if request.direction else cost
        stats["shares"] = held
        return outcome, ok, detail, stats
