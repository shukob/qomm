"""The share the node computes on is the share the dealer committed to.

`BINDING.md` opens with the gap this closes, and `policy_audit.py` used to state
it in its own docstring: the shares it commits to *are not* the shares MP-SPDZ
consumes. Two sharings of the same policy existed --- Pedersen VSS over the
group's scalar field on the audit side, additive over the integers on the
circuit side --- and nothing anywhere compared them. A maker could have one
policy audited and a different one computed, and every check would pass.

**What closes it is not new cryptography.** It is making the two sharings one
sharing, which needs only that the MPC run over the field a share is an element
of. `BINDING.md` section 2 measured that at 1.00x rounds and 2.00x traffic, so
the price was known before this was written.

The chain, and what each link would fail to catch on its own:

    1. commit          a Pedersen commitment per field         (hides the value)
    2. range           the value is inside the venue's band    (nothing else says so)
    3. share           Pedersen VSS of value and blinding      (this is step 1's value,
                                                                by construction --- the
                                                                same call makes both)
    4. node check      every node opens its own share against
                       the coefficient commitments             (a share the dealer
                                                                did not commit to)
    5. read            the circuit rebuilds the value from all
                       n shares by public Lagrange             (this is step 3's sharing,
                                                                because the same object
                                                                was written to the party
                                                                files)
    6. input check     the node fed the share it was dealt     (a node that substitutes;
                                                                `zk/input_check.py`)

Steps 1 through 5 are here. Step 6 already existed and is orthogonal --- it
catches the node, where this catches the dealer. Both are needed and neither
implies the other, which is why `BINDING.md` section 4 calls the input check
defence in depth rather than a substitute.

It lives here rather than in `zk/` because the dependency runs one way. `zk` is
the proof library and knows nothing about this system's input stream; this
module is about that stream, and sits beside `roles.py`, which is the dealing it
replaces. Putting it the other way round shipped a `zk` that imported
`qomm_transport`, in a repository that does not carry it.

**The order of the input stream is known in exactly one place**, and it is not
this one. `mp_spdz.gen_qomm.position_of` is where to ask what sits where, for
the same reason the hook exists at all. `build_inputs`
in `mp_spdz/gen_qomm.py` knows it, and this module passes it a hook rather than
reproducing it. Reproducing it is what produced the bug being fixed.

**The threshold does not change, though it looks like it should.** Additive
sharing across all `n` needs every node to reconstruct an input; Shamir needs
`t+1`. But `secret_input()` hands the value to MP-SPDZ, which holds it as a
degree-`t` sharing from that moment on, so any `t+1` nodes could always have
reconstructed it. The additive layer was buying a stronger guarantee than the
protocol underneath it, which is not a guarantee.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from zk.commit import Pedersen, RangeProof, prove_bounded, verify_bounded
from zk.groups import Group
from zk.policy_audit import FieldCommitment, PolicyShare

from .roles import lagrange_at_zero

BINDING_DOMAIN = b"qomm:binding:v1"


@dataclass(frozen=True)
class DealtValue:
    """One value: what was published about it, and what each node was given."""

    position: int                  # where in the input stream the circuit reads it
    commitment: FieldCommitment    # the value commitment and the VSS coefficients
    shares: tuple[PolicyShare, ...]
    label: str = ""


@dataclass(frozen=True)
class BoundInputs:
    """A whole input stream, published and dealt in one pass."""

    prime: int
    n_parties: int
    threshold: int
    values: tuple[DealtValue, ...]
    ranges: Mapping[int, RangeProof] = field(default_factory=dict)

    @property
    def lagrange(self) -> list[int]:
        return lagrange_at_zero(self.n_parties, self.prime)

    def party_file(self, party: int) -> list[int]:
        """Party `party`'s input file, in the order the circuit reads it."""
        return [dealt.shares[party].value_share for dealt in self.values]

    def commitments(self) -> list[Any]:
        return [dealt.commitment.commitment for dealt in self.values]


class BindingDealer:
    """Commits, shares and records, in the one pass that writes the party files.

    Used as `build_inputs(..., deal_hook=dealer)`. Every value the circuit will
    read goes through `__call__`, so nothing can be committed and not dealt, or
    dealt and not committed --- the two are the same statement about the same
    object.
    """

    def __init__(self, group: Group, n_parties: int, threshold: int,
                 key: Pedersen | None = None, rng: random.Random | None = None,
                 labels: Sequence[str] = ()):
        if n_parties < 2 * threshold + 1:
            raise ValueError(f"{n_parties} parties cannot carry a threshold of "
                             f"{threshold}")
        self.group = group
        self.key = key or Pedersen(group, BINDING_DOMAIN)
        self.n_parties = n_parties
        self.threshold = threshold
        self.rng = rng or random.Random()
        self.labels = list(labels)
        self.dealt: list[DealtValue] = []
        self.blindings: list[int] = []

    def _scalar(self) -> int:
        return self.rng.randrange(self.group.order)

    def __call__(self, value: int, position: int) -> list[int]:
        """Commit to `value`, share it, keep the public part, hand back the shares.

        The return value is what goes into the party files. Everything else is
        kept here, which is what makes it impossible for the files and the
        commitments to describe different numbers.
        """
        group, order = self.group, self.group.order
        value_poly = [value % order] + [self._scalar() for _ in range(self.threshold)]
        blind_poly = [self._scalar() for _ in range(self.threshold + 1)]
        coefficients = tuple(self.key.commit(value_poly[k], blind_poly[k])
                             for k in range(self.threshold + 1))
        shares = []
        for party in range(1, self.n_parties + 1):
            v = sum(value_poly[k] * pow(party, k, order)
                    for k in range(self.threshold + 1)) % order
            b = sum(blind_poly[k] * pow(party, k, order)
                    for k in range(self.threshold + 1)) % order
            shares.append(PolicyShare(party, v, b))
        label = self.labels[position] if position < len(self.labels) else ""
        self.dealt.append(DealtValue(position, FieldCommitment(coefficients[0],
                                                               coefficients),
                                     tuple(shares), label))
        self.blindings.append(blind_poly[0])
        return [share.value_share for share in shares]

    def bound(self, ranges: Mapping[int, RangeProof] | None = None) -> BoundInputs:
        return BoundInputs(prime=self.group.order, n_parties=self.n_parties,
                           threshold=self.threshold, values=tuple(self.dealt),
                           ranges=dict(ranges or {}))

    def prove_range(self, position: int, value: int, low: int, high: int,
                    context: bytes = b"") -> RangeProof:
        """That one dealt value is inside the venue's band, without opening it.

        `prove_bounded` commits to the value itself, so the commitment it
        returns has to be the one already published for this position. It is,
        because the same blinding is used --- and that identity is asserted
        rather than assumed, since if it ever stopped holding the range proof
        would be about a different number than the shares are.
        """
        commitment, proof, _ = prove_bounded(
            self.key, value, self.blindings[position], low, high,
            context=context + b":" + str(position).encode())
        published = self.dealt[position].commitment.commitment
        if self.group.encode(commitment) != self.group.encode(published):
            raise ValueError(f"the range proof at position {position} is about a "
                             f"different commitment than the one dealt")
        return proof


def check_share(key: Pedersen, dealt: DealtValue, party: int) -> bool:
    """What one node runs before it computes on anything.

    `party` is the index into the shares, so node 0 holds `f(1)`. The check is
    the VSS one --- the share opens against the polynomial's coefficient
    commitments --- and it is the only thing standing between a node and
    computing on a number nobody promised.
    """
    group = key.group
    share = dealt.shares[party]
    expected = group.identity()
    for k, coefficient in enumerate(dealt.commitment.coefficient_commitments):
        expected = group.mul(expected, group.point_pow(
            coefficient, pow(share.party, k, group.order)))
    return group.encode(key.commit(share.value_share, share.blinding_share)) == \
        group.encode(expected)


def check_all(key: Pedersen, bound: BoundInputs) -> list[tuple[int, int]]:
    """Every node against every value it was handed. Returns what failed."""
    return [(party, dealt.position)
            for dealt in bound.values
            for party in range(bound.n_parties)
            if not check_share(key, dealt, party)]


def reconstruct(bound: BoundInputs, position: int) -> int:
    """What the circuit will compute, from the shares it will be given.

    Not part of the protocol --- no party runs this, because running it is
    exactly what the sharing exists to prevent. It is here so a test can say
    that the value the circuit rebuilds is the value that was committed to,
    which is the claim this module is making.
    """
    dealt = bound.values[position]
    total = sum(coefficient * share.value_share
                for coefficient, share in zip(bound.lagrange, dealt.shares))
    total %= bound.prime
    return total - bound.prime if total > bound.prime // 2 else total


def check_range(key: Pedersen, bound: BoundInputs, position: int, low: int,
                high: int, context: bytes = b"") -> bool:
    """The published commitment for that position is inside the band."""
    proof = bound.ranges.get(position)
    if proof is None:
        return False
    return verify_bounded(key, bound.values[position].commitment.commitment,
                          proof, low, high,
                          context=context + b":" + str(position).encode())
