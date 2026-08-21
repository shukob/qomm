"""The three gaps: registered rule digests, bad partials, real relay hops."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qomm_dsl.language import compile_rule                                    # noqa: E402
from qomm_dsl.registry import RuleRegistry, rule_digest                       # noqa: E402
from zk.commit import Pedersen, verify_opening                                # noqa: E402
from zk.groups import make_group                                              # noqa: E402
from scripts.measure import value                                             # noqa: E402
from zk.threshold_sigma import deal, joint_prove_opening                      # noqa: E402

SOURCE = (ROOT / "qomm_dsl" / "examples" / "quote.rule").read_text()


@pytest.fixture(scope="module")
def group():
    return make_group("ed25519")


# --- registered rule form -------------------------------------------------

def test_the_approved_rule_is_accepted():
    registry = RuleRegistry()
    entry = registry.approve(SOURCE, "quote")
    assert registry.check(SOURCE, "quote", entry.digest) == (True, "ok")


def test_a_substituted_formula_is_detected():
    registry = RuleRegistry()
    entry = registry.approve(SOURCE, "quote")
    swapped = SOURCE.replace("+ mid + half", "+ mid + half + half")
    # a replacement that matches nothing leaves the source alone, and the test
    # then checks that an unmodified rule verifies --- which it does, silently.
    assert swapped != SOURCE, "the tamper this test performs no longer applies"
    ok, reason = registry.check(swapped, "quote", entry.digest)
    assert not ok and "substituted" in reason


def test_a_widened_bound_is_detected():
    registry = RuleRegistry()
    entry = registry.approve(SOURCE, "quote")
    widened = SOURCE.replace("half[1,200]", "half[1,2000]")
    assert not registry.check(widened, "quote", entry.digest)[0]


def test_an_unregistered_digest_is_refused():
    registry = RuleRegistry()
    registry.approve(SOURCE, "quote")
    ok, reason = registry.check(SOURCE, "quote", "00" * 32)
    assert not ok and "not an approved" in reason


def test_the_digest_ignores_comments_and_spacing():
    """Only the shape, the bounds and the circuit are covered, not the layout."""
    a = rule_digest(compile_rule(SOURCE, "quote"))
    b = rule_digest(compile_rule("# a note\n\n" + SOURCE, "quote"))
    assert a == b


def test_the_digest_covers_the_required_width():
    registry = RuleRegistry()
    entry = registry.approve(SOURCE, "quote")
    assert entry.required_bits == compile_rule(SOURCE, "quote").required_bits()


# --- attributing a bad partial in the joint proof -------------------------

def test_an_honest_quorum_reports_no_bad_partials(group):
    key = Pedersen(group)
    parties = list(range(1, 8))
    shares = deal(key, 4_242, key.random_blinding(), parties, threshold=2)
    proof, transcript = joint_prove_opening(key, shares, [1, 2, 3])
    assert transcript["bad_partials"] == []
    assert verify_opening(key, shares.commitment, proof)


def test_a_bad_partial_is_attributed_to_its_node(group):
    key = Pedersen(group)
    parties = list(range(1, 8))
    shares = deal(key, 4_242, key.random_blinding(), parties, threshold=2)
    quorum = [1, 2, 3]
    proof, transcript = joint_prove_opening(
        key, shares, quorum, faulty={2: (12345, 6789)})
    assert transcript["bad_partials"] == [2]
    # and the resulting proof does not verify, so the fault is not silently absorbed
    assert not verify_opening(key, shares.commitment, proof)


def test_every_node_can_be_named_in_turn(group):
    key = Pedersen(group)
    parties = list(range(1, 8))
    shares = deal(key, 99, key.random_blinding(), parties, threshold=2)
    quorum = [2, 4, 6]
    for culprit in quorum:
        _, transcript = joint_prove_opening(
            key, shares, quorum, faulty={culprit: (1, 1)})
        assert transcript["bad_partials"] == [culprit]


def test_the_transcript_records_what_each_node_sent(group):
    key = Pedersen(group)
    parties = list(range(1, 8))
    shares = deal(key, 7, key.random_blinding(), parties, threshold=2)
    _, transcript = joint_prove_opening(key, shares, [1, 3, 5])
    assert set(transcript["partial_commitments"]) == {1, 3, 5}
    assert set(transcript["partial_responses"]) == {1, 3, 5}


# --- relay hops are real sockets ------------------------------------------

def test_every_relay_hop_costs_a_connection():
    """A cascade that passed batches in memory would report a free hop."""
    import asyncio
    import random

    sys.path.insert(0, str(ROOT / "scripts"))
    from run_transport import analyse, run_session

    timings = {}
    for hops in (1, 3):
        session = asyncio.run(run_session(6, 3, 8, 10.0, 0.4, seed=3, hops=hops))
        report = analyse(session, 6, 3, 8)
        assert report["frames_delivered"] == report["expected_frames"]
        assert report["traffic_identical"]
        timings[hops] = value(report["slot_wall_s"])
    assert timings[3] > timings[1], "extra hops must show up in the measurement"
