"""The shares the prover reads are the shares the circuit computed on.

The quote proof is assembled from shares. Until the circuit kept them, those
shares reached the prover by a route of their own -- the circuit computed a
winner, the prover was handed values, and nothing said the two were the same
numbers. A proof about numbers that merely agree with a computation is not a
proof about the computation, and that gap was the largest thing the design had
been asserting rather than showing.

The fixture is a real run: seven parties, malicious-secure honest-majority
Shamir at T=2, four makers, over MP-SPDZ's default 128-bit field. The circuit
opened a winner the cleartext reference already predicts, and each node wrote
its share of that winner. If the reader below reconstructs the same number, the
share the prover would take as witness is the share the circuit produced.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mp_spdz.persistence import (                                      # noqa: E402
    from_montgomery, read, reconstruct, recover,
)

FIXTURE = Path(__file__).parent / "fixtures" / "persistence"
PARTIES = 7
THRESHOLD = 2

# What the circuit opened, from the cleartext reference of the same run:
# best price 100029 at maker 2, packed over 4 padded makers.
EXPECTED = 100029 * 4 + 2


def test_every_node_wrote_in_the_same_field():
    files = [read(FIXTURE / f"Transactions-P{p}.data", p) for p in range(PARTIES)]
    primes = {f.prime for f in files}
    assert len(primes) == 1, f"the nodes wrote in {len(primes)} different fields"
    assert all(len(f.shares) == 1 for f in files)


def test_the_shares_reconstruct_the_answer_the_circuit_opened():
    assert recover(FIXTURE, PARTIES, THRESHOLD) == EXPECTED


def test_every_quorum_of_three_agrees():
    """Any T+1 reconstruct the same value, which is what makes it a secret
    sharing rather than seven numbers that happen to be lying around."""
    files = [read(FIXTURE / f"Transactions-P{p}.data", p) for p in range(PARTIES)]
    prime = files[0].prime
    values = {f.party: from_montgomery(f.shares[0], prime, f.element_bytes)
              for f in files}
    import itertools
    seen = {reconstruct([(p + 1, values[p]) for p in subset], prime)
            for subset in itertools.combinations(range(PARTIES), THRESHOLD + 1)}
    assert seen == {EXPECTED}


def test_a_node_that_kept_a_different_share_is_noticed(tmp_path):
    """The check has to fail when it should, or it is not a check."""
    for p in range(PARTIES):
        raw = bytearray((FIXTURE / f"Transactions-P{p}.data").read_bytes())
        if p == 3:
            raw[-1] ^= 0x01
        (tmp_path / f"Transactions-P{p}.data").write_bytes(bytes(raw))
    with pytest.raises(ValueError, match="do not agree"):
        recover(tmp_path, PARTIES, THRESHOLD)


def test_fewer_shares_than_the_threshold_say_nothing():
    """Two of seven reconstruct a different number, which is the point of T=2."""
    files = [read(FIXTURE / f"Transactions-P{p}.data", p) for p in range(PARTIES)]
    prime = files[0].prime
    values = {f.party: from_montgomery(f.shares[0], prime, f.element_bytes)
              for f in files}
    two = reconstruct([(1, values[0]), (2, values[1])], prime)
    assert two != EXPECTED, "two shares recovered the secret at threshold two"
