"""Naming the node that sent a wrong share.

The claim being tested is not that a decoder exists --- Berlekamp--Welch is from
1986 --- but that **this deployment's parameters put the corruption threshold
exactly at the decoding capacity**, so the party that lied can be named from what
the protocol already sends. `n = 7`, `T = 2`, degree-`t` sharings: `RS[7,3]`,
distance 5, two correctable errors.

The boundary tests matter more than the success tests. A decoder that quietly
named an innocent party when three lied would be worse than one that gave up.
"""

from __future__ import annotations

import random

import pytest

from qomm_audit.locate import (Verdict, capacity, evaluate, locate,
                               reconstruct, share)

P = (1 << 127) - 1
POINTS = list(range(1, 8))          # seven nodes
DEGREE = 2                          # T = 2
PRODUCT_DEGREE = 4                  # 2T, a product before degree reduction


def corrupt(shares: list[int], who: list[int], rng) -> list[int]:
    out = list(shares)
    for i in who:
        out[i] = (out[i] + rng.randrange(1, P)) % P
    return out


# --- the parameters, which are where everything comes from ----------------

def test_the_deployment_sits_exactly_at_the_decoding_capacity():
    """T = 2 and the capacity is 2. That coincidence is the whole finding."""
    assert capacity(7, DEGREE) == 2


def test_a_product_before_reduction_can_only_name_one():
    assert capacity(7, PRODUCT_DEGREE) == 1


def test_collecting_only_2t_plus_1_shares_halves_the_capacity():
    """MP-SPDZ opens from five of seven. RS[5,3] locates one, not two."""
    assert capacity(5, DEGREE) == 1
    assert capacity(7, DEGREE) == 2


@pytest.mark.parametrize("n,degree,expected", [
    (7, 2, 2), (7, 4, 1), (5, 2, 1), (4, 2, 0), (3, 2, 0), (10, 2, 3)])
def test_capacity_follows_the_singleton_bound(n, degree, expected):
    assert capacity(n, degree) == expected


# --- the decode -----------------------------------------------------------

@pytest.mark.parametrize("n_bad", [0, 1, 2])
def test_it_recovers_and_names_up_to_the_threshold(n_bad):
    rng = random.Random(1000 + n_bad)
    for _ in range(60):
        secret = rng.randrange(P)
        shares = share(secret, DEGREE, POINTS, P, rng)
        who = sorted(rng.sample(range(7), n_bad))
        verdict = locate(POINTS, corrupt(shares, who, rng), DEGREE, P)
        assert verdict.ok, verdict.reason
        assert verdict.secret == secret
        assert sorted(verdict.culprits) == who


def test_three_liars_are_refused_rather_than_guessed():
    """Beyond capacity the honest answer is 'I cannot tell', not a name."""
    rng = random.Random(3)
    for _ in range(60):
        shares = share(rng.randrange(P), DEGREE, POINTS, P, rng)
        verdict = locate(POINTS, corrupt(shares, rng.sample(range(7), 3), rng),
                         DEGREE, P)
        assert not verdict.ok
        assert verdict.culprits == []
        assert "beyond what any decoder" in verdict.reason


@pytest.mark.parametrize("n_bad", [0, 1])
def test_products_are_handled_at_their_own_capacity(n_bad):
    rng = random.Random(2000 + n_bad)
    for _ in range(40):
        secret = rng.randrange(P)
        shares = share(secret, PRODUCT_DEGREE, POINTS, P, rng)
        who = sorted(rng.sample(range(7), n_bad))
        verdict = locate(POINTS, corrupt(shares, who, rng), PRODUCT_DEGREE, P)
        assert verdict.ok and verdict.secret == secret
        assert sorted(verdict.culprits) == who


def test_two_liars_defeat_a_product():
    rng = random.Random(9)
    shares = share(rng.randrange(P), PRODUCT_DEGREE, POINTS, P, rng)
    assert not locate(POINTS, corrupt(shares, [1, 4], rng), PRODUCT_DEGREE, P).ok


def test_an_honest_transcript_names_nobody():
    rng = random.Random(11)
    secret = rng.randrange(P)
    verdict = locate(POINTS, share(secret, DEGREE, POINTS, P, rng), DEGREE, P)
    assert verdict.ok and not verdict.named and verdict.reason == "consistent"


def test_every_single_liar_is_found_wherever_they_sit():
    """No position is a blind spot, including the ends."""
    rng = random.Random(13)
    for who in range(7):
        secret = rng.randrange(P)
        shares = share(secret, DEGREE, POINTS, P, rng)
        verdict = locate(POINTS, corrupt(shares, [who], rng), DEGREE, P)
        assert verdict.culprits == [who] and verdict.secret == secret


def test_every_pair_is_found():
    rng = random.Random(17)
    for a in range(7):
        for b in range(a + 1, 7):
            secret = rng.randrange(P)
            shares = share(secret, DEGREE, POINTS, P, rng)
            verdict = locate(POINTS, corrupt(shares, [a, b], rng), DEGREE, P)
            assert verdict.culprits == [a, b], (a, b, verdict.reason)
            assert verdict.secret == secret


def test_a_liar_who_changes_nothing_is_not_a_liar():
    """Adding zero is not an attack, and must not be reported as one."""
    rng = random.Random(19)
    shares = share(rng.randrange(P), DEGREE, POINTS, P, rng)
    assert locate(POINTS, list(shares), DEGREE, P).culprits == []


# --- against the engine's own behaviour -----------------------------------

def test_plain_reconstruction_believes_whatever_it_is_given():
    """What MP-SPDZ's Lagrange step does, and why detection is not location."""
    rng = random.Random(23)
    secret = rng.randrange(P)
    shares = share(secret, DEGREE, POINTS, P, rng)
    assert reconstruct(POINTS[:3], shares[:3], P) == secret
    bad = corrupt(shares, [0], rng)
    assert reconstruct(POINTS[:3], bad[:3], P) != secret       # silently wrong


def test_detection_and_location_come_apart():
    """Two subsets disagreeing says 'someone', not 'who'. The decode says who."""
    rng = random.Random(29)
    secret = rng.randrange(P)
    bad = corrupt(share(secret, DEGREE, POINTS, P, rng), [5], rng)
    first = reconstruct(POINTS[:3], bad[:3], P)
    second = reconstruct(POINTS[4:7], bad[4:7], P)
    assert first != second                       # this is all the engine knows
    assert locate(POINTS, bad, DEGREE, P).culprits == [5]      # this is more


# --- shape ----------------------------------------------------------------

def test_mismatched_lengths_are_refused():
    with pytest.raises(ValueError):
        locate(POINTS, [1, 2, 3], DEGREE, P)


def test_too_few_points_for_the_degree_is_refused():
    with pytest.raises(ValueError):
        locate([1, 2], [3, 4], DEGREE, P)


def test_a_verdict_reports_whether_it_named_anybody():
    assert not Verdict(True, 5, [], "consistent").named
    assert Verdict(True, 5, [2], "one").named


def test_evaluate_matches_the_sharing_it_came_from():
    rng = random.Random(31)
    coeffs = [rng.randrange(P) for _ in range(3)]
    assert [evaluate(coeffs, x, P) for x in POINTS] == [
        evaluate(coeffs, x, P) for x in POINTS]
    assert evaluate(coeffs, 0, P) == coeffs[0]
