"""The share layer, run for real so a seat can misbehave and be caught.

What is real here and what is not, stated before anything else, because a demo
that blurs this is worse than no demo.

**Real.** Inputs are split with `qomm_transport.roles.split`, the same additive
dealing the generator writes into the party files, and committed with the same
Pedersen key the rest of the tree uses. Every product of two secrets goes
through a Shamir multiplication in the Damgard--Nielsen shape: local product to
degree `2t`, mask with a random double sharing, open, subtract. The opening is
decoded with `qomm_audit.locate`, which is Berlekamp--Welch, so a node that
sends a consistent-looking wrong share is corrected and named by arithmetic
rather than by a script. The final opening is decoded the same way.

**Not real.** The tournament that picks the winner is computed in the clear.
Comparing two secret prices needs bit decomposition, and building that here
would be building a second MPC engine next to the one this project already
measures. Point the demo at `--engine mpc` and the whole round runs in MP-SPDZ
instead, tournament included.

**Three ways to cheat, three different endings.** They are different rungs of
`ACCOUNTABILITY.md` and the demo exists mostly to make the difference felt.

    lie_product   a wrong share of a masked product. Corrected, the liar named,
                  the protocol does not stop --- while at most `capacity` do it.
    lie_open      a wrong share at the final opening. Decoded and named too, but
                  from a degree-`t` sharing, so the capacity is larger.
    lie_input     a share other than the one it was dealt. Nothing is
                  inconsistent: it is a valid sharing of a different number.
                  Nothing detects it and nobody is named --- unless the dealer's
                  share commitments are checked, which is what the switch is
                  for, and then the node is named before it computes anything.

Going silent is two cases, not one, and telling them apart is the point of
having both. A node that never turns up takes the *input* phase down with it:
inputs are dealt additively across all `n` nodes, so one missing share destroys
every value, and no amount of decoding helps because nothing is inconsistent ---
it is absent. A node that answers the inputs and then stops leaves the
multiplications running with one fewer evaluation point, which costs decoding
capacity: at nine nodes and `T = 2` the products go from surviving two liars to
surviving one. Robustness was built for the degree reduction and for nothing
else, and this is where a demo either says so or misleads.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from qomm_audit.locate import capacity, locate, reconstruct, share
from qomm_transport.roles import SLACK_BITS, split

# Wide enough that a 32-bit value dealt into nine additive shares with 40 bits
# of slack still reconstructs exactly, and small enough to stay quick in Python.
PRIME = (1 << 127) - 1

HONEST = "honest"
LIE_PRODUCT = "lie_product"
LIE_OPEN = "lie_open"
LIE_INPUT = "lie_input"
OFFLINE = "offline"
DROPOUT = "dropout"
BEHAVIOURS = (HONEST, LIE_PRODUCT, LIE_OPEN, LIE_INPUT, DROPOUT, OFFLINE)

VALUE_BITS = 32


@dataclass
class Reduction:
    """One masked product opened, decoded, and put back at degree t."""

    label: str
    ok: bool
    named: list[int] = field(default_factory=list)
    reason: str = ""


@dataclass
class Rejection:
    """A node whose stated share is not the one its commitment says it holds.

    Produced by checking a commitment, never by knowing who cheated. The check
    is given the stated shares and the dealings and nothing else, so a demo run
    where it names the right node is evidence and not stagecraft.
    """

    node: int
    dealer: str
    position: int


@dataclass
class Transcript:
    """Everything the round did at the share level. No seat sees all of it."""

    n_nodes: int
    threshold: int
    silent: list[int] = field(default_factory=list)
    reductions: list[Reduction] = field(default_factory=list)
    named: dict[int, int] = field(default_factory=dict)     # node -> times named
    rejected: list[Rejection] = field(default_factory=list)
    open_named: list[int] = field(default_factory=list)
    aborted: bool = False
    abort_reason: str = ""
    # The same fact twice: a code the browser renders in whatever language it
    # is set to, and English prose for the log and for anyone reading the
    # transcript. The code is the one that must not drift, so the prose is
    # built from the same fields rather than written beside them.
    abort_code: str = ""
    abort_fields: dict = field(default_factory=dict)
    shares_seen: dict[int, list[str]] = field(default_factory=dict)
    product_capacity: int = 0
    open_capacity: int = 0
    commit_ms: float = 0.0
    # Node seats whose chosen behaviour the running engine cannot carry out.
    # Named so the browser can grey the switch instead of pretending.
    inert_behaviours: list = field(default_factory=list)
    corrupted_inputs: list[int] = field(default_factory=list)

    @property
    def corrections(self) -> int:
        return sum(1 for r in self.reductions if r.named)

    def stop(self, code: str, reason: str, **fields) -> None:
        self.aborted = True
        self.abort_code = code
        self.abort_reason = reason
        self.abort_fields = fields

    def name(self, who: list[int]) -> None:
        for node in who:
            self.named[node] = self.named.get(node, 0) + 1


class Session:
    """One round's worth of share arithmetic across a fixed set of nodes.

    Constructed per round rather than kept, because the double sharings a
    multiplication consumes must not be reused --- reusing one would open the
    same mask twice and the difference of the two openings is the difference of
    the two products.
    """

    def __init__(self, n_nodes: int, threshold: int, behaviours: dict[int, str],
                 rng: random.Random | None = None):
        if n_nodes < 2 * threshold + 1:
            raise ValueError(f"{n_nodes} nodes cannot carry a threshold of "
                             f"{threshold}: reconstruction needs {2*threshold+1}")
        self.n = n_nodes
        self.t = threshold
        self.behaviour = {j: behaviours.get(j, HONEST) for j in range(n_nodes)}
        self.rng = rng or random.Random()
        self.points = list(range(1, n_nodes + 1))
        # absent for the whole round, against absent from here on
        self.absent = [j for j in range(n_nodes) if self.behaviour[j] == OFFLINE]
        self.live = [j for j in range(n_nodes)
                     if self.behaviour[j] not in (OFFLINE, DROPOUT)]
        self.transcript = Transcript(
            n_nodes=n_nodes, threshold=threshold,
            silent=[j for j in range(n_nodes) if self.behaviour[j] == OFFLINE])
        live_points = len(self.live)
        self.transcript.product_capacity = max(0, capacity(live_points, 2 * threshold))
        self.transcript.open_capacity = max(0, capacity(live_points, threshold))
        self._liars_product = [j for j in self.live
                               if self.behaviour[j] == LIE_PRODUCT]
        self._liars_open = [j for j in self.live if self.behaviour[j] == LIE_OPEN]

    # --- what a node holds ---------------------------------------------------

    def deal(self, values: list[int]) -> list[list[int]]:
        """One additive share of every value to every node, over the integers.

        All `n` shares are needed to get the value back, so this is the step a
        missing node kills outright.
        """
        columns = [split(int(v), self.n, VALUE_BITS, self.rng) for v in values]
        return [[column[j] for column in columns] for j in range(self.n)]

    def inputs_possible(self) -> bool:
        """Whether every share of every input exists to be summed."""
        if not self.absent:
            return True
        who = ", ".join(f"node {j}" for j in self.absent)
        self.transcript.stop(
            "absent",
            f"{who} did not take part. Inputs are split additively across all "
            f"{self.n} nodes, so a missing share is a missing value --- nothing "
            f"is inconsistent, so nothing can be decoded. Robustness covers the "
            f"degree reduction, not this.",
            who=list(self.absent), n=self.n)
        return False

    def substituted(self, held: list[list[int]], target: int = 1,
                    shift: int | None = None) -> tuple[list[list[int]], list[int]]:
        """What each node actually feeds in, which need not be what it was dealt.

        Returned separately from what it was dealt, because the gap between the
        two is the whole point: an additive share is not bound to anything, so a
        node can shift the sum and every downstream check still passes.

        `target` is a position in the input stream and defaults to the taker's
        size, which is the substitution an adversary would actually pick: move
        it up and every maker's limit refuses the order, move it down and the
        taker is charged for a smaller trade than it gets. Shifting a position
        at random would be more dramatic and less honest --- most of eighty-odd
        positions belong to makers who were not going to win, so a random shift
        usually changes nothing at all, and a demo that relied on luck to make
        its point would be making a different point.
        """
        stated = [list(row) for row in held]
        moved = []
        for j in self.live:
            if self.behaviour[j] == LIE_INPUT and stated[j]:
                where = min(target, len(stated[j]) - 1)
                stated[j][where] += (shift if shift is not None
                                     else self.rng.randrange(1, 400))
                moved.append(j)
        self.transcript.corrupted_inputs = moved
        return stated, moved

    # --- the multiplication, in the shape the engine uses --------------------

    def _share_t(self, value: int) -> list[int]:
        return share(value % PRIME, self.t, self.points, PRIME, self.rng)

    def multiply(self, a: int, b: int, label: str) -> int | None:
        """`a*b` computed through shares, with the opening decoded.

        The value is what a correct run produces; `None` means the round could
        not go on, and the transcript says why. Both arguments arrive in the
        clear because the callers hold them in the clear --- what is being
        exercised is the opening and its decoder, which is where a node that
        sends something consistent-but-wrong has to be caught.
        """
        a_shares, b_shares = self._share_t(a), self._share_t(b)
        r = self.rng.randrange(PRIME)
        r_2t = share(r, 2 * self.t, self.points, PRIME, self.rng)
        r_t = share(r, self.t, self.points, PRIME, self.rng)

        masked = [(a_shares[j] * b_shares[j] + r_2t[j]) % PRIME
                  for j in range(self.n)]
        for j in self._liars_product:
            masked[j] = (masked[j] + self.rng.randrange(1, PRIME)) % PRIME

        points = [self.points[j] for j in self.live]
        received = [masked[j] for j in self.live]
        if len(points) < 2 * self.t + 1:
            self.transcript.stop(
                "too_few",
                f"only {len(points)} nodes answered; a degree-{2*self.t} sharing "
                f"needs {2*self.t + 1} to reconstruct at all",
                answered=len(points), needed=2 * self.t + 1, degree=2 * self.t)
            self.transcript.reductions.append(
                Reduction(label, ok=False, reason=self.transcript.abort_reason))
            return None

        verdict = locate(points, received, 2 * self.t, PRIME)
        if not verdict.ok:
            self.transcript.stop(
                "beyond_capacity",
                f"{label}: {verdict.reason}. A degree-{2*self.t} sharing over "
                f"{len(points)} answering nodes corrects "
                f"{self.transcript.product_capacity}",
                capacity=self.transcript.product_capacity, answered=len(points),
                degree=2 * self.t, where="product")
            self.transcript.reductions.append(
                Reduction(label, ok=False, reason=self.transcript.abort_reason))
            return None
        named = sorted(self.live[i] for i in verdict.culprits)
        self.transcript.reductions.append(Reduction(label, ok=True, named=named))
        self.transcript.name(named)

        # e is public now, so putting the product back at degree t is one local
        # subtraction --- which is why removing the king costs a round and not
        # a protocol.
        e = verdict.secret
        product_shares = [(e - r_t[j]) % PRIME for j in range(self.n)]
        recovered = reconstruct(self.points[:self.t + 1], product_shares[:self.t + 1],
                                PRIME)
        return signed(recovered)

    # --- the last opening ----------------------------------------------------

    def open_value(self, value: int, label: str = "quote") -> int | None:
        """Open one degree-`t` sharing, decoding rather than believing it."""
        shares = self._share_t(value)
        for j in self._liars_open:
            shares[j] = (shares[j] + self.rng.randrange(1, PRIME)) % PRIME
        points = [self.points[j] for j in self.live]
        received = [shares[j] for j in self.live]
        if len(points) < self.t + 1:
            self.transcript.stop(
                "too_few",
                f"only {len(points)} nodes answered the opening; "
                f"{self.t + 1} are needed",
                answered=len(points), needed=self.t + 1, degree=self.t)
            return None
        verdict = locate(points, received, self.t, PRIME)
        if not verdict.ok:
            self.transcript.stop(
                "beyond_capacity",
                f"{label}: {verdict.reason}. The opening corrects "
                f"{self.transcript.open_capacity}",
                capacity=self.transcript.open_capacity, answered=len(points),
                degree=self.t, where="opening")
            return None
        named = sorted(self.live[i] for i in verdict.culprits)
        self.transcript.open_named = named
        self.transcript.name(named)
        return signed(verdict.secret)


def signed(value: int) -> int:
    """Field elements back to the integers they stand for."""
    return value - PRIME if value > PRIME // 2 else value
