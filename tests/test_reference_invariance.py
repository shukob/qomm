"""The winner does not depend on the reference price, and the price is affine in it.

This is what decides whether a slow committee produces a stale quote. The
reference enters every maker's quote as the same additive term --- `anchored =
mid + spread_request(ref)` --- and none of the eligibility gates reads it, so a
move in the reference shifts every cost by the same amount and cannot reorder
them. A computation that took a while can therefore run against whatever
reference was current when it started, and the revealed price be corrected by
how far the reference moved since; the winner needs no correction because it was
never wrong.

The correction costs no rounds: it is a secret one-hot vector times public
constants, which is local, and in the single-asset case it is a public addition.

The property is load-bearing for wide-area deployment, so it is tested rather
than remembered.
"""

from __future__ import annotations

import pytest

from mp_spdz.gen_qomm import build_inputs

BASE = 100_000
MOVES = (0, 1, 5, 50, 500, -7, -300)


def answer(reference: int, direction: int, seed: int, qty: int = 40) -> dict:
    _, reference_answer = build_inputs(
        n_mm=16, n_real_mm=16, n_parties=7, is_real=1, n_requests=1,
        n_assets=1, ref_table=[reference], user_asset=0, user_qty=qty,
        user_dir=direction, user_entity=0, now_t=1000, ref_mid=reference,
        seed=seed)
    return reference_answer


@pytest.mark.parametrize("direction", (0, 1))
@pytest.mark.parametrize("seed", (7, 11, 23, 99, 1234))
def test_winner_is_invariant_to_the_reference(direction: int, seed: int) -> None:
    winners = {answer(BASE + move, direction, seed)["best_mm"] for move in MOVES}
    assert len(winners) == 1, (
        f"the reference reordered the makers: {winners}. A wide-area quote could "
        f"then not be corrected after the fact, only recomputed.")


@pytest.mark.parametrize("direction", (0, 1))
@pytest.mark.parametrize("seed", (7, 11, 23, 99, 1234))
def test_price_is_affine_in_the_reference(direction: int, seed: int) -> None:
    # the cost minimised is `d ? -bid : ask`, so the reference enters with the
    # sign of the side --- one sign per request, which is why it still cannot
    # reorder anything.
    sign = 1 if direction == 0 else -1
    residuals = {answer(BASE + move, direction, seed)["best_cost"] - sign * (BASE + move)
                 for move in MOVES}
    assert len(residuals) == 1, (
        f"the price is not a fixed offset from the reference: {sorted(residuals)}")


def test_the_correction_is_what_a_late_quote_needs() -> None:
    """A quote computed at one reference, corrected to another, equals the direct one."""
    for direction in (0, 1):
        sign = 1 if direction == 0 else -1
        started_at = answer(BASE, direction, seed=31)
        for drift in (3, 40, -25):
            corrected = started_at["best_cost"] + sign * drift
            direct = answer(BASE + drift, direction, seed=31)
            assert corrected == direct["best_cost"]
            assert started_at["best_mm"] == direct["best_mm"]
