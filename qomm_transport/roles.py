"""Who shares a secret, and who computes on it. They are not the same parties.

The design has always said this and the code did not. A request was read with
`sint.get_input_from(0)` and a market maker's policy with
`get_input_from(i % N_PARTIES)`, so on the executed path computing node 0 held
the whole request --- including `is_real`, the flag that separates a live
request from cover --- and one computing node held each maker's whole policy.
Everything downstream is a benchmark of a circuit with party-supplied inputs,
which is a different claim from the one the design makes.

Three roles, and none of them is two of the others:

  Trader          one per request. Splits the request and never computes.
  MarketMaker     one per maker. Splits its policy and never computes.
  ComputingNode   one of N. Holds one share of everything and no whole value.

**How a secret crosses the boundary.** Each input party splits its value into N
shares that sum *over the integers* to the value, and hands share p to node p.
The program adds the N inputs back together, which is local arithmetic and free
in rounds. Summing over the integers rather than modulo the field is what makes
this work without knowing which prime MP-SPDZ chose: the reconstruction is
exact as long as the field is wider than the shares, which `check_field_width`
requires rather than assumes.

Hiding is statistical, not perfect. A share is uniform over
`2^(value_bits + SLACK_BITS)`, so one share is within 2^-SLACK_BITS of uniform
whatever the value was --- the standard price for not having to match moduli.
Nothing here is a substitute for input consistency under a malicious majority:
these shares are additive and a node that lies about its share shifts the sum.
That check belongs with the resharing step and is not in this file.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Iterable

# How much wider than the value a share is drawn. A share then hides the value
# to within 2^-40, which is the usual statistical margin for this construction.
SLACK_BITS = 40


def split(value: int, n_nodes: int, value_bits: int, rng=None) -> list[int]:
    """`value` as n_nodes integers that sum to it, each hiding it statistically.

    Signed values are allowed: `value_bits` is the width of the magnitude, and a
    negative value is split the same way because the sum is over the integers.
    """
    if n_nodes < 2:
        raise ValueError("sharing needs at least two nodes")
    if value.bit_length() > value_bits:
        raise ValueError(f"value needs {value.bit_length()} bits, "
                         f"declared {value_bits}")
    rng = rng or secrets.SystemRandom()
    span = 1 << (value_bits + SLACK_BITS)
    shares = [rng.randrange(span) for _ in range(n_nodes - 1)]
    shares.append(value - sum(shares))
    return shares


def check_field_width(n_nodes: int, value_bits: int, field_bits: int) -> None:
    """Refuse a field the reconstruction would wrap in.

    The sum of N shares is at most N * 2^(value_bits + SLACK_BITS) in magnitude,
    and it has to be representable, signs included.
    """
    needed = value_bits + SLACK_BITS + (n_nodes - 1).bit_length() + 2
    if field_bits < needed:
        raise ValueError(
            f"a {field_bits}-bit field cannot hold {n_nodes} shares of a "
            f"{value_bits}-bit value: {needed} bits are needed. Widen the field "
            f"or lower the slack, and say which in the artifact.")


@dataclass
class ComputingNode:
    """One of N. It receives shares and never sees a value they came from."""

    index: int
    inputs: list[int] = field(default_factory=list)

    def receive(self, share: int) -> None:
        self.inputs.append(share)


@dataclass
class InputParty:
    """Someone with a secret and no part in computing on it."""

    name: str
    n_nodes: int
    value_bits: int

    def deal(self, values: Iterable[int], nodes: list[ComputingNode], rng=None) -> None:
        """Hand each node its share of every value, in the order the program reads them."""
        if len(nodes) != self.n_nodes:
            raise ValueError("dealing to a different number of nodes than declared")
        for value in values:
            for node, share in zip(nodes, split(value, self.n_nodes,
                                                self.value_bits, rng)):
                node.receive(share)


class Trader(InputParty):
    """The party a request belongs to. Also supplies the mask its answer comes back under."""


class MarketMaker(InputParty):
    """The party a price policy belongs to."""
