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


def test_the_cleartext_model_does_not_see_the_sentinel() -> None:
    """The bound the two tests above cannot reach, stated and checked.

    The cleartext reference skips ineligible makers with `continue`, but the
    circuit gives them `LARGE` instead --- and `LARGE` does not move with the
    reference. So the correction is valid only while a corrected cost stays
    below the sentinel, and the tests above, which run on the cleartext model,
    cannot detect that boundary. It is arithmetic rather than a measurement:
    the sentinel is built as 8x the largest reference, and the circuit's own
    headroom check refuses a configuration where it would not fit.
    """
    from mp_spdz.gen_qomm import sentinel_for

    # the shipped configuration: 31-bit values, 16 makers, a reference near 1e5
    reference_price = 100_000
    sentinel = sentinel_for(31, 16, 8 * reference_price)
    # a maker's own terms are tens of ticks (mid in [-15,15], half in [5,40],
    # depth and skew a few hundred at the fixture's sizes), so the corrected
    # cost is the new reference plus a small offset.
    room = sentinel / reference_price
    assert room > 100, (
        f"the reference could only move {room:.0f}x before an eligible quote "
        f"collided with the sentinel; a correction is basis points, but this "
        f"margin is configuration-dependent and should not shrink silently")


def test_a_narrow_field_is_refused_rather_than_silently_wrong() -> None:
    """The headroom check is what keeps the bound above from being a hope."""
    import pytest as _pytest

    with _pytest.raises(ValueError, match="too narrow"):
        # 16 bits cannot pack 16 makers with costs up to 8e5
        sentinel_for_narrow = __import__(
            "mp_spdz.gen_qomm", fromlist=["sentinel_for"]).sentinel_for
        sentinel_for_narrow(16, 16, 8 * 100_000)


# ---- the reference as something a maker opts into --------------------------
#
# Everything else in the policy can already be switched off by setting its
# coefficient to zero: `slope`, `invcoef` and `active` all admit 0. The
# reference used to be the exception, added with a hard-wired coefficient of
# one, which forced every maker onto a benchmark whether or not the market had
# a usable one. `use_ref` is that missing switch.


def answer_with(reference: int, use_ref: int, direction: int = 0,
                seed: int = 7) -> dict:
    _, reference_answer = build_inputs(
        n_mm=16, n_real_mm=16, n_parties=7, is_real=1, n_requests=1,
        n_assets=1, ref_table=[reference], user_asset=0, user_qty=40,
        user_dir=direction, user_entity=0, now_t=1000, ref_mid=reference,
        seed=seed, use_ref=use_ref)
    return reference_answer


@pytest.mark.parametrize("seed", (7, 11, 23))
def test_a_maker_on_the_reference_tracks_it(seed: int) -> None:
    prices = [answer_with(BASE + move, use_ref=1, seed=seed)["best_cost"]
              for move in (0, 50, 500)]
    assert prices == [BASE + (p - BASE) for p in prices]      # sanity
    assert prices[1] - prices[0] == 50
    assert prices[2] - prices[0] == 500


@pytest.mark.parametrize("seed", (7, 11, 23))
def test_a_maker_off_the_reference_does_not(seed: int) -> None:
    """A market with no usable benchmark: the maker carries the level itself."""
    prices = {answer_with(BASE + move, use_ref=0, seed=seed)["best_cost"]
              for move in (0, 50, 500, -300)}
    assert len(prices) == 1, (
        f"the reference still reached a maker that switched it off: {prices}")


@pytest.mark.parametrize("seed", (7, 11, 23))
def test_switching_the_reference_off_does_not_change_who_wins(seed: int) -> None:
    """The flag scales the level, not the ordering, so the winner is the same."""
    on = answer_with(BASE, use_ref=1, seed=seed)
    off = answer_with(BASE, use_ref=0, seed=seed)
    assert on["best_mm"] == off["best_mm"]
    assert on["best_cost"] - off["best_cost"] == BASE


def test_mixing_the_switch_inside_one_market_costs_the_invariance() -> None:
    """Two makers that disagree about the reference can be reordered by it.

    This is the price of putting the switch on the maker rather than on the
    market. When every maker on an asset treats the reference the same way, a
    move in it shifts them all equally and cannot reorder them --- which is what
    the correction in `DEPLOYMENT.md` section 0.5 relies on. When they disagree,
    a move shifts only some of them, and the winner can change.

    The alternative costs nothing at all: a market with no usable benchmark is a
    zero row in the public reference table, and then every maker on that asset
    is treated identically again. The maker-side switch buys the choice and
    gives up the correction; the table-side one does the reverse.
    """
    def quote(use_ref: int, mid: int, reference: int) -> int:
        return use_ref * reference + mid

    on_the_reference = {"use_ref": 1, "mid": 30}
    off_it = {"use_ref": 0, "mid": 100_020}

    winners = set()
    for reference in (99_980, 100_000, 100_020, 100_040):
        a = quote(reference=reference, **on_the_reference)
        b = quote(reference=reference, **off_it)
        winners.add("relative" if a < b else "absolute")
    assert winners == {"relative", "absolute"}, (
        "the two makers were never reordered, so this stopped demonstrating "
        "what it is here to demonstrate")
