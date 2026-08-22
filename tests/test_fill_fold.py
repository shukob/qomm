"""The fill comparison rides the tournament's last layer.

`--binding-limit` used to emit `fill = (best_key <= limit_key)` after the
tournament had finished, which is one comparison paying full depth on its own
while every comparison inside the tournament runs sixteen wide and amortises.
Measured, that cost +9 rounds against a prediction of +2 to +8.

`min(a, b) <= L` is decided by `a <= L` and `b <= L`, and both operands exist
before the last level runs, so the comparison can join a layer that was going
to run anyway. Measured after the fold: +2 rounds, and one more comparison's
worth of bytes. These tests check the shape of the emitted program, which is
what a machine without MP-SPDZ can check; `artifacts/fill_fold.json` carries
the rounds.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def emit(tmp_path, *extra: str) -> str:
    subprocess.run(
        [sys.executable, str(ROOT / "mp_spdz" / "gen_qomm.py"),
         "--n-mm", "16", "--n-parties", "7",
         "--out-program", str(tmp_path / "q.mpc"),
         "--out-input-dir", str(tmp_path / "in"),
         "--out-reference", str(tmp_path / "ref.json"), *extra],
        check=True, capture_output=True)
    return (tmp_path / "q.mpc").read_text()


def test_the_standalone_comparison_after_the_tournament_is_gone(tmp_path):
    source = emit(tmp_path, "--binding-limit")
    assert "argmin_fill" in source
    assert "fill = (best_key <= limit_key)" not in source


def test_the_last_level_compares_three_pairs_where_it_compared_one(tmp_path):
    """(a,b), (a,L) and (b,L) in one layer, then two selects in the next."""
    source = emit(tmp_path, "--binding-limit")
    body = source.split("def argmin_fill")[1].split("\ndef ")[0]
    # one comparison over a three-lane vector, not three comparisons
    assert body.count("<=") >= 1
    assert "left.get_vector() <= right.get_vector()" in body
    assert "while size > 2:" in body       # the loop stops one level short
    # two selects after the loop --- the winner and the fill bit --- against
    # the one the loop's own levels do
    last = body.split("bits.assign(")[1]
    assert last.count("if_else") == 2


def test_the_kary_tournament_folds_too(tmp_path):
    """Arity 4 gets the same treatment, through the split-out level function."""
    source = emit(tmp_path, "--binding-limit", "--argmin-arity", "4")
    assert "def kary_level(" in source
    assert "while size > arity:" in source
    body = source.split("def argmin_fill")[1].split("\ndef ")[0]
    # the diagonal of the square is the fill comparison, the rest is the rank
    assert "finalists[p] if p != q else limit" in body


def test_nothing_is_emitted_when_there_is_no_limit(tmp_path):
    """No dead code in the program that does not bind."""
    source = emit(tmp_path)
    assert "argmin_fill" not in source
    assert "limit_key" not in source


def test_the_measurement_says_what_the_fold_bought(tmp_path):
    """The artifact, so the claim in ACCOUNTABILITY.md has a file behind it."""
    held = json.loads((ROOT / "artifacts" / "fill_fold.json").read_text())
    arms = {a["arm"]: a for a in held["arms"]}
    assert arms["plain"]["rounds"] == 70
    assert arms["standalone"]["rounds"] == 79
    assert arms["folded"]["rounds"] == 72
    # bytes went the other way: one more comparison than the standalone arm
    assert arms["folded"]["global_mb"] > arms["standalone"]["global_mb"]
