"""Defects that were fixed but that nothing would catch coming back.

Each of these once shipped, ran, and passed the suite. The suite passed because
none of them break an interface --- they break a meaning, and a test that pins a
meaning has to be written on purpose. Appendix I of the paper records what they
were; this file is what stops them returning.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qomm_sim.market import SimConfig                                # noqa: E402
from qomm_sim.tapes import TapeMarket, load_bybit, requests_from_tape  # noqa: E402


# --- a tape written newest-first, read in file order ------------------------

@pytest.fixture
def descending_tape(tmp_path):
    """Exchanges write these files newest-first, which is easy not to notice."""
    path = tmp_path / "DESC2021-06-15.csv"
    lines = ["timestamp,symbol,side,size,price,tickDirection,trdMatchID"]
    for index in range(400):
        stamp = 1_623_801_600 - index          # counting down, as the real files do
        side = "Buy" if index % 3 else "Sell"
        lines.append(f"{stamp}.0,DESC,{side},{1 + index % 7},{100 + index % 11},"
                     f"ZeroTick,id{index}")
    path.write_text("\n".join(lines) + "\n")
    return path


def test_a_tape_written_newest_first_spreads_across_its_span(descending_tape):
    """Reading in file order gave negative step indices, silently.

    Checking only that no index is negative is not enough, and the first version
    of this test made exactly that mistake: the loader clamped negatives to zero,
    so an unsorted tape produced a market where every trade happened in the first
    step --- which loads, runs, and reports numbers. What has to be checked is
    that time actually passes.
    """
    cfg = SimConfig()
    tape = load_bybit(descending_tape, cfg, steps=600, step_ms=1_000)
    steps = [row[0] for row in tape.rows]
    assert steps, "the loader dropped every row"
    assert steps == sorted(steps), "rows are not in time order"
    assert steps[0] == 0, f"the tape does not start at its own beginning: {steps[0]}"
    assert steps[-1] > 0.5 * len(steps), (
        f"every trade landed in the first {steps[-1]} steps: the rows were not "
        f"sorted and the clamp hid it")
    assert len(set(steps)) > 1, "all trades share one step"


def test_the_price_series_follows_time_and_not_file_order(descending_tape):
    """A mid built in file order runs backwards through the day."""
    cfg = SimConfig()
    tape = load_bybit(descending_tape, cfg, steps=600, step_ms=1_000)
    assert len(tape.mid) == 601
    assert all(value > 0 for value in tape.mid)


# --- an informedness label the attacker can recompute -----------------------

def test_informedness_is_not_a_function_of_what_the_attacker_sees(descending_tape):
    """The label was once a threshold on the attacker's own score.

    Attacker 5 scores a settled trade by the signed move that followed it.
    Labelling a request informed exactly when that move cleared a threshold made
    the label a deterministic function of the score, and the attacker reported
    0.9987 --- a measurement of the labelling rule and not of the attack.
    """
    cfg = SimConfig(steps=600, window_steps=60)
    tape = load_bybit(descending_tape, cfg, steps=600, step_ms=1_000)
    market = TapeMarket(cfg, tape, seed=3)
    requests, cfg, _ = requests_from_tape(cfg, market, tape, synthetic_entities=8)

    # the quantity the attacker scores on, per request
    scored = []
    for request in requests:
        move = market.move(request.step, market.horizon)
        signed = move if request.direction == 0 else -move
        scored.append((signed, request.informed))

    informed = [s for s, flag in scored if flag]
    uninformed = [s for s, flag in scored if not flag]
    if not informed or not uninformed:
        pytest.skip("this tape produced only one class")

    # If the label were a threshold on the score, the two classes would not
    # overlap. Requiring overlap is exactly requiring the label to carry
    # something the attacker cannot read off.
    assert min(informed) <= max(uninformed), (
        "every informed request scores above every uninformed one: the label is "
        "recoverable from the attacker's own quantity")


def test_the_informed_share_is_estimated_from_agreement(descending_tape):
    """Uninformed flow agrees half the time, so the excess is the estimate."""
    cfg = SimConfig(steps=600, window_steps=60)
    tape = load_bybit(descending_tape, cfg, steps=600, step_ms=1_000)
    market = TapeMarket(cfg, tape, seed=3)
    assert 0.0 <= market.informed_share <= 1.0
    expected = max(0.0, min(1.0, 2.0 * market.agreement_rate - 1.0))
    assert market.informed_share == pytest.approx(expected)


# --- relays that all closed on one clock ------------------------------------

def test_relays_do_not_share_a_slot_boundary():
    """Closing every hop on one command prices the shuffling and not the waiting.

    In a deployment each relay keeps its own clock, so a batch handed on just
    after the next hop's boundary waits for the one after it --- up to a whole
    slot, not the two milliseconds it takes to hand bytes over in one process.
    """
    import asyncio

    sys.path.insert(0, str(ROOT / "scripts"))
    from run_transport import run_session

    session = asyncio.run(run_session(
        n_clients=3, n_nodes=3, n_slots=2, slot_ms=25.0, activity=0.5,
        seed=5, hops=3, link_ms=5.0))
    phases = session["phases"]
    assert len(phases) == 3
    assert len(set(round(p, 6) for p in phases)) > 1, (
        "every relay closed at the same offset: the harness shares one clock")
    assert all(0.0 <= p <= 25.0 for p in phases)


def test_a_link_delay_between_relays_is_actually_paid():
    """A hop that costs nothing is a hop that was passed in memory."""
    import asyncio

    sys.path.insert(0, str(ROOT / "scripts"))
    from run_transport import run_session

    slots = []
    for link_ms in (0.0, 12.0):
        session = asyncio.run(run_session(
            n_clients=3, n_nodes=3, n_slots=3, slot_ms=25.0, activity=0.5,
            seed=5, hops=3, link_ms=link_ms))
        slots.append(sorted(session["slot_wall"])[len(session["slot_wall"]) // 2])
    assert slots[1] > slots[0], (
        f"adding {12.0} ms to each of two crossings changed nothing: {slots}")


def test_snr_model_matches_the_mechanism_it_describes():
    """The derivation in the paper is only worth reading if it reproduces the
    mechanism's own noise scale. If DPParams changes and this stops matching,
    the appendix is describing a mechanism that no longer exists."""
    import math

    from qomm_sim.disclosure import discrete_laplace  # noqa: F401  (import guard)
    from qomm_sim.experiment import DPParams
    from qomm_sim.market import SIZE_BUCKETS, SimConfig

    dp, cfg = DPParams(), SimConfig()
    eps_field = dp.epsilon_per_window / 4
    assert dp.volume_cap / eps_field == 1200.0

    mean_size = sum(w * (lo + hi) / 2
                    for w, (lo, hi) in zip((0.55, 0.33, 0.12), SIZE_BUCKETS))
    per_firm_per_s = cfg.arrival_rate * (1000 / cfg.step_ms) / cfg.n_entities
    t_star = (dp.volume_cap / mean_size) ** 2 / per_firm_per_s
    assert 225 < t_star < 240, t_star

    # Median basis, because the figure it is compared against is a median.
    ceiling = 0.6745 * eps_field * math.sqrt(cfg.n_entities)
    assert 0.80 < ceiling < 0.86, ceiling
    # and the measured value has to sit under its own ceiling, or one of the two
    # is wrong
    assert 0.36 < ceiling
