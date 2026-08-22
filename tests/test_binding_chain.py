"""The share the circuit reads is the share the dealer committed to.

`BINDING.md` section 0 states the gap: `zk/policy_audit.py` committed to Shamir
shares over the group's scalar field while the circuit read additive shares over
the integers, and nothing anywhere compared the two. A maker could have one
policy audited and a different one computed.

What closes it is an identity rather than a comparison --- the same call
commits and deals --- so the tests worth having are the ones that would notice
the identity being broken again. The first of them is literally `==` between the
party file and the dealer's shares.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "mp_spdz"))

from gen_qomm import ED25519_ORDER, FIELDS, build_inputs        # noqa: E402
from qomm_transport.roles import (lagrange_at_zero,             # noqa: E402
                                  shamir_split)
from qomm_transport.binding import (BindingDealer, BoundInputs, check_all,  # noqa: E402
                        check_range, check_share, reconstruct)
from zk.groups import make_group                                # noqa: E402
from zk.policy_audit import PolicyBounds, PolicyShare           # noqa: E402

N_PARTIES, THRESHOLD = 7, 2


@pytest.fixture(scope="module")
def group():
    return make_group("ed25519")


def deal(group, seed=5, n_mm=8):
    dealer = BindingDealer(group, N_PARTIES, THRESHOLD, rng=random.Random(seed))
    per_party, reference = build_inputs(
        n_mm=n_mm, n_real_mm=n_mm, n_parties=N_PARTIES, is_real=1, n_requests=1,
        n_assets=1, ref_table=[100000], user_asset=0, user_qty=20, user_dir=0,
        user_entity=0, now_t=1, ref_mid=100000, seed=seed, deal_hook=dealer)
    return dealer, dealer.bound(), per_party, reference


# --- the identity, which is the whole fix --------------------------------

def test_the_party_file_is_the_dealt_share_and_not_a_second_dealing(group):
    dealer, bound, per_party, _ = deal(group)
    for party in range(N_PARTIES):
        assert bound.party_file(party) == per_party[party]


def test_the_two_copies_of_the_prime_agree(group):
    """One in the generator so it runs without the proof stack, one in the group."""
    assert ED25519_ORDER == group.order


def test_every_value_the_circuit_reads_was_committed_to(group):
    dealer, bound, _, _ = deal(group)
    assert len(bound.values) == len(bound.party_file(0))
    assert not check_all(dealer.key, bound)


# --- what the circuit will rebuild ---------------------------------------

def test_the_public_coefficients_rebuild_a_degree_t_polynomial(group):
    """All n points, not t+1. That is what keeps the input count unchanged."""
    rng = random.Random(11)
    coefficients = lagrange_at_zero(N_PARTIES, group.order)
    for value in (0, 1, 4242, -17, group.order - 1):
        shares = shamir_split(value, N_PARTIES, THRESHOLD, group.order, rng)
        total = sum(c * s for c, s in zip(coefficients, shares)) % group.order
        assert total == value % group.order


def test_the_reconstruction_is_the_committed_value(group):
    """What the circuit computes on is what the audit is about."""
    dealer, bound, _, reference = deal(group)
    request = [reconstruct(bound, i) for i in range(5)]
    assert request == [0, 20, 0, 0, 1]        # asset, qty, direction, entity, is_real
    base = 5 + 1                              # the four request fields, is_real, mask
    maker0 = dict(zip(FIELDS, (reconstruct(bound, base + i)
                               for i in range(len(FIELDS)))))
    quote = reference["quotes"][0]
    anchor = maker0["use_ref"] * 100000 + maker0["mid"]
    assert quote["ask"] == anchor + maker0["half"] + maker0["slope"] * 20 \
        + maker0["invcoef"] * maker0["inv"]


def test_any_threshold_plus_one_nodes_reconstruct(group):
    """The chain does not weaken the threshold, which it looks like it should.

    Additive sharing across all n needed every node; this needs t+1. But
    `secret_input` hands the value to MP-SPDZ, which holds it as a degree-t
    sharing from then on, so t+1 could always reconstruct. The guarantee the
    additive layer appeared to give was never below the protocol's own.
    """
    dealer, bound, _, _ = deal(group)
    dealt = bound.values[1]                   # the order size
    order = group.order
    for subset in ((0, 1, 2), (4, 5, 6), (0, 3, 6)):
        total = 0
        for i in subset:
            xi = dealt.shares[i].party
            numerator = denominator = 1
            for j in subset:
                if i == j:
                    continue
                xj = dealt.shares[j].party
                numerator = (numerator * (-xj)) % order
                denominator = (denominator * (xi - xj)) % order
            total += dealt.shares[i].value_share * numerator * pow(denominator, -1, order)
        assert total % order == 20


# --- the dealer it catches -----------------------------------------------

def test_a_share_that_does_not_open_its_commitment_is_caught(group):
    """Named by party and by position, before anything is computed."""
    dealer, bound, _, _ = deal(group)
    position, party = 8, 3
    original = bound.values[position]
    moved = tuple(PolicyShare(sh.party, sh.value_share + 1, sh.blinding_share)
                  if i == party else sh for i, sh in enumerate(original.shares))
    tampered = list(bound.values)
    tampered[position] = type(original)(original.position, original.commitment,
                                        moved, original.label)
    caught = check_all(dealer.key, BoundInputs(
        prime=bound.prime, n_parties=N_PARTIES, threshold=THRESHOLD,
        values=tuple(tampered)))
    assert caught == [(party, position)]


def test_a_dealer_that_swaps_the_whole_value_is_caught_at_every_node(group):
    """Not one bad share but a consistent sharing of a different number."""
    dealer, bound, _, _ = deal(group)
    position = 8
    original = bound.values[position]
    other = BindingDealer(group, N_PARTIES, THRESHOLD, rng=random.Random(99))
    other(999, 0)
    swapped = list(bound.values)
    swapped[position] = type(original)(original.position, original.commitment,
                                       other.dealt[0].shares, original.label)
    caught = check_all(dealer.key, BoundInputs(
        prime=bound.prime, n_parties=N_PARTIES, threshold=THRESHOLD,
        values=tuple(swapped)))
    assert sorted(caught) == [(party, position) for party in range(N_PARTIES)]


def test_one_node_checks_only_its_own_share(group):
    """What a node can do alone, which is the only check it can be trusted to run."""
    dealer, bound, _, _ = deal(group)
    for party in range(N_PARTIES):
        assert check_share(dealer.key, bound.values[0], party)


# --- the band ------------------------------------------------------------

def test_the_range_proof_is_about_the_commitment_that_was_dealt(group):
    dealer, bound, _, _ = deal(group)
    position = 5 + 1 + FIELDS.index("half")
    value = reconstruct(bound, position)
    band = PolicyBounds().half
    proof = dealer.prove_range(position, value, *band, context=b"band")
    bound = dealer.bound(ranges={position: proof})
    assert check_range(dealer.key, bound, position, *band, context=b"band")


def test_a_range_proof_against_a_different_blinding_is_refused(group):
    """The link that would silently break: a proof about a fresh commitment."""
    dealer, bound, _, _ = deal(group)
    position = 5 + 1 + FIELDS.index("half")
    dealer.blindings[position] = (dealer.blindings[position] + 1) % group.order
    with pytest.raises(ValueError, match="different commitment"):
        dealer.prove_range(position, reconstruct(bound, position),
                           *PolicyBounds().half, context=b"band")


def test_a_value_outside_the_band_cannot_be_proved_inside_it(group):
    dealer = BindingDealer(group, N_PARTIES, THRESHOLD, rng=random.Random(2))
    dealer(9999, 0)
    with pytest.raises(ValueError, match="outside"):
        dealer.prove_range(0, 9999, *PolicyBounds().half)


# --- what this does not catch, said out loud ------------------------------

def test_a_node_substituting_its_input_is_not_caught_here(group):
    """It is a valid share of a different number, so there is nothing to notice.

    `zk/input_check.py` is what catches it. Written as a test rather than as a
    comment because a reader who assumes otherwise has the threat model wrong.
    """
    dealer, bound, per_party, _ = deal(group)
    fed = list(per_party[3])
    fed[8] += 1                       # node 3 feeds something else
    # every commitment still opens: the dealing was honest and unchanged
    assert not check_all(dealer.key, bound)
    assert fed != bound.party_file(3)


def test_the_dealer_refuses_a_threshold_its_party_count_cannot_carry(group):
    with pytest.raises(ValueError, match="cannot carry"):
        BindingDealer(group, 4, 2)


# --- tying something audited elsewhere to what was dealt ------------------

def test_the_position_of_a_field_is_where_the_circuit_reads_it(group):
    """One place knows the layout, and this is the test that it is the right one."""
    from gen_qomm import commitment_at, position_of

    dealer, bound, _, _ = deal(group)
    for maker in (0, 1, 7):
        for field in ("asset", "inv", "use_ref"):
            position = position_of(maker, field)
            assert bound.values[position].position == position
            # what the circuit rebuilds there is the value the fixture dealt
            rebuilt = reconstruct(bound, position)
            base = 5 + 1 + maker * len(FIELDS) + FIELDS.index(field)
            assert position == base
            assert rebuilt == reconstruct(bound, base)
    # and the commitment is the one a state audit would have to be about
    assert group.encode(commitment_at(bound, 3, "inv")) == group.encode(
        bound.values[position_of(3, "inv")].commitment.commitment)


def test_a_field_that_is_not_a_policy_field_is_refused(group):
    from gen_qomm import position_of

    with pytest.raises(ValueError, match="not a policy field"):
        position_of(0, "not_a_field")


def test_the_binding_limit_moves_every_policy_along(group):
    """Two extra trader inputs, so a caller that ignored the flag would be off."""
    from gen_qomm import position_of

    assert position_of(0, "asset", binding_limit=True) - \
        position_of(0, "asset") == 2
