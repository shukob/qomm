"""Reading back the shares the circuit kept, and checking they are the answer's.

The quote proof is assembled from shares, and until now those shares reached the
prover by a route of their own: the circuit computed a winner, the prover was
handed values, and nothing said the two were the same numbers. A proof about
numbers that merely agree with the computation is not a proof about the
computation.

`sint.write_to_file` makes the circuit keep each node's share where the prover
reads it. This module is the other end of that: it parses MP-SPDZ's persistence
format and reconstructs, so the identity can be *checked* rather than assumed.

The format was read off the bytes and then confirmed against a known result ---
a circuit whose answer the cleartext reference already gives --- because a new
reader that has not reproduced something known is not a reader anyone should
trust. Three things about it are not obvious and each was found the hard way:
the share is little-endian, it is in Montgomery form, and the evaluation points
are one-based.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from pathlib import Path

# `Shamir gfp` writes a 35-byte type string: the name, the element size, the
# prime, and flags. The prime is the sixteen bytes at offset 15, big-endian.
PRIME_OFFSET = 15
PRIME_BYTES = 16


@dataclass(frozen=True)
class Persisted:
    """One node's file: the field it was written in, and its shares."""

    party: int
    prime: int
    element_bytes: int
    shares: list[int]


def read(path: Path, party: int) -> Persisted:
    raw = Path(path).read_bytes()
    length = int.from_bytes(raw[:8], "little")
    header = raw[8:8 + length]
    if not header.startswith(b"Shamir gfp"):
        raise ValueError(f"{path}: not a Shamir gfp persistence file "
                         f"({header[:16]!r})")
    prime = int.from_bytes(header[PRIME_OFFSET:PRIME_OFFSET + PRIME_BYTES], "big")
    # `Shamir gfp` then one byte, then the element size as a little-endian
    # u32, then the prime. Reading the size from one byte earlier gives 4096,
    # which is the kind of mistake a fixture catches and a comment does not.
    element = int.from_bytes(header[11:15], "little") or PRIME_BYTES
    body = raw[8 + length:]
    if len(body) % element:
        raise ValueError(f"{path}: {len(body)} bytes is not a whole number of "
                         f"{element}-byte shares")
    shares = [int.from_bytes(body[i:i + element], "little") % prime
              for i in range(0, len(body), element)]
    return Persisted(party=party, prime=prime, element_bytes=element, shares=shares)


def from_montgomery(value: int, prime: int, element_bytes: int) -> int:
    """MP-SPDZ keeps field elements multiplied by R. Divide it back out."""
    r = 1 << (8 * element_bytes)
    return value * pow(r, -1, prime) % prime


def reconstruct(points: list[tuple[int, int]], prime: int) -> int:
    """Lagrange at zero. `points` are (evaluation point, share)."""
    total = 0
    for i, (xi, yi) in enumerate(points):
        numerator, denominator = 1, 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            numerator = numerator * (-xj) % prime
            denominator = denominator * (xi - xj) % prime
        total = (total + yi * numerator * pow(denominator, -1, prime)) % prime
    return total


def recover(directory: Path, parties: int, threshold: int, index: int = 0) -> int:
    """The `index`-th written value, from any threshold-plus-one of the nodes.

    Every subset has to agree. One that does not means a node kept a share of
    something other than what the circuit computed, which is the thing this
    function exists to notice.
    """
    files = [read(Path(directory) / f"Transactions-P{p}.data", p)
             for p in range(parties)]
    prime = files[0].prime
    if any(f.prime != prime for f in files):
        raise ValueError("the nodes did not write in the same field")
    values = {f.party: from_montgomery(f.shares[index], prime, f.element_bytes)
              for f in files}

    answers = set()
    for subset in itertools.combinations(sorted(values), threshold + 1):
        # Shamir evaluation points are one-based: party p holds f(p + 1)
        answers.add(reconstruct([(p + 1, values[p]) for p in subset], prime))
    if len(answers) != 1:
        raise ValueError(
            f"the nodes' shares do not agree: {len(answers)} different values "
            "reconstruct from different subsets, so at least one node kept a "
            "share of something the circuit did not compute")
    return answers.pop()
