"""Seats, and what each one is allowed to know.

The room holds one taker seat, one seat per maker, one per computing node, and
any number of observers. A seat is *automatic* until somebody claims it, and
goes back to automatic when they leave or press the button, so the same program
runs on one laptop with nobody at the controls and in a room where nine people
each hold a node.

The rule that matters is in `view`. The round is computed once, in full, and
then projected onto each seat --- and a projection can only ever delete. No seat
except an observer is handed the full result and asked not to look, because a
demo whose privacy story is enforced in the browser is a demo of nothing. The
observer seat exists for the screen at the front of the room and says on every
frame that it is a view nobody in a deployment has.

What comes back from a round is a masked key, `best_key + mask`, exactly as the
circuit opens it: it packs the price and the winning maker together and it is
uniform to everyone who does not hold the taker's mask. So the makers do not
learn who won either. Somebody has to tell them, and in the demo that is the
taker pressing a button --- which is the honest shape of it, and is worth seeing
happen rather than being told about.
"""

from __future__ import annotations

import random
import secrets
import time
from dataclasses import dataclass, field

import hashlib
import secrets as _secrets

from qomm_transport.roles import Dealing, check_share

from .model import BUY, FIELDS, SELL, Outcome, Policy, Request, evaluate
from .protocol import BEHAVIOURS, HONEST, LIE_PRODUCT, Rejection, Session


class HashCommitment:
    """Binding and hiding on one value, from hashlib and nothing else.

    The rest of this tree commits with Pedersen over ed25519, and a deployment
    has to: Pedersen commitments multiply, so the shares' commitments can be
    required to add up to the value's, and that is what catches a *dealer* that
    signs shares which do not sum to the value it meant. `BINDING.md` is about
    that gap and what closing it costs.

    The check in this demo is the other one --- has this node stated the share
    it was dealt --- and for that, binding one value is the whole requirement.
    A hash gives it, needs nothing installed, and is fast enough that the check
    can be on by default. So the difference is not a shortcut taken here; it is
    that the two checks want different things, and only one of them is running.

    It presents the small surface `qomm_transport.roles.check_share` uses, so
    the check itself is the shipped one rather than a copy.
    """

    class _Encoding:
        # `check_share` compares encodings rather than objects, and a digest is
        # already its own encoding.
        order = 1 << 252

        @staticmethod
        def encode(value):
            return value

    group = _Encoding()

    def __init__(self, label: bytes = b"qomm:demo:v1"):
        self.label = label

    def commit(self, value: int, blinding: int) -> bytes:
        body = (self.label + b":"
                + int(value).to_bytes(72, "big", signed=True)
                + int(blinding).to_bytes(32, "big"))
        return hashlib.sha256(body).digest()

    def random_blinding(self) -> int:
        return _secrets.randbits(128)


COMMIT_KEY = HashCommitment()

TAKER, MAKER, NODE, OBSERVER = "taker", "maker", "node", "observer"


@dataclass
class Asset:
    name: str
    reference: int
    scale: int = 100

    def show(self, ticks: int | None) -> str:
        if ticks is None:
            return "--"
        return f"{ticks / self.scale:,.{len(str(self.scale)) - 1}f}"


DEFAULT_ASSETS = [
    Asset("USD/JPY", 15750, 100),
    Asset("EUR/USD", 10850, 10000),
    Asset("BTC/USD", 6420000, 100),
]


@dataclass
class Seat:
    id: str
    kind: str
    index: int
    label: str = ""
    holder: str | None = None
    # A seat forced to manual with nobody in it stalls rather than acting, which
    # is sometimes what you want to show and is never what you want by accident.
    forced_manual: bool = False

    @property
    def manual(self) -> bool:
        return self.holder is not None or self.forced_manual

    @property
    def mode(self) -> str:
        return "manual" if self.manual else "auto"


@dataclass
class Notice:
    """One line for the seat it belongs to, as a code rather than a sentence.

    The browser renders it, because the browser is the only thing that knows
    which language the person reading it chose. Writing the sentence here would
    mean writing it twice, and the second copy would be the one that goes stale.
    """

    at: float
    code: str
    fields: dict = field(default_factory=dict)
    tone: str = "info"          # info | good | warn | bad


@dataclass
class RoundResult:
    number: int
    engine: str
    request: Request
    outcome: Outcome
    masked_key: int
    mask: int
    padded: int
    named: dict[int, int]
    rejected: list
    reductions: int
    corrections: int
    aborted: bool
    abort_reason: str
    abort_code: str
    abort_fields: dict
    product_capacity: int
    open_capacity: int
    silent: list
    corrupted_inputs: list
    input_check: bool
    ms: float
    verified: bool | None = None
    verified_detail: str = ""
    engine_stats: dict = field(default_factory=dict)
    announced: bool = False
    node_shares: dict = field(default_factory=dict)
    # The policies the round actually priced with. Not the same object as the
    # room's: the automatic makers move between rounds, so showing the live
    # ones beside a finished round's quotes would caption each row with a
    # policy that did not produce it.
    used_policies: list = field(default_factory=list)

    def unpack(self) -> tuple[int | None, int | None]:
        """What the taker recovers from the masked key: the cost and the winner."""
        if self.outcome.winner is None:
            return None, None
        cost, maker = divmod(self.masked_key - self.mask, self.padded)
        return cost, maker


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(int(value), high))


def _dealer_of(position: int) -> str:
    """Which input party a position in the stream belongs to."""
    if position < 5:
        return "the taker"
    return f"maker {(position - 5) // len(FIELDS)}"


def _pow2_ceil(n: int) -> int:
    p = 1
    while p < n:
        p *= 2
    return p


class Room:
    """One market, one set of seats, one round at a time."""

    def __init__(self, n_makers: int = 8, n_nodes: int = 9, threshold: int = 2,
                 assets: list[Asset] | None = None, engine=None,
                 input_check: bool = True, seed: int | None = None):
        self.assets = assets or list(DEFAULT_ASSETS)
        self.n_makers = n_makers
        self.n_nodes = n_nodes
        self.threshold = threshold
        self.rng = random.Random(seed)
        self.engine = engine
        self.input_check = input_check
        self.round_number = 0
        self.now_t = 0
        self.history: list[RoundResult] = []
        self.last: RoundResult | None = None
        self.notices: dict[str, list[Notice]] = {}
        self.phase = "idle"
        self.phase_detail = ""

        self.seats: dict[str, Seat] = {"taker": Seat("taker", TAKER, 0)}
        for i in range(n_makers):
            self.seats[f"maker:{i}"] = Seat(f"maker:{i}", MAKER, i)
        for j in range(n_nodes):
            self.seats[f"node:{j}"] = Seat(f"node:{j}", NODE, j)

        self.policies: list[Policy] = [self._starting_policy(i)
                                       for i in range(n_makers)]
        self.behaviour: dict[int, str] = {j: HONEST for j in range(n_nodes)}
        self.request = Request(asset=0, qty=100, direction=BUY, is_real=1)
        self.sessions: dict[str, str] = {}      # session token -> seat id

    # --- configuration -------------------------------------------------------

    def _starting_policy(self, index: int) -> Policy:
        asset = index % len(self.assets)
        return Policy(asset=asset,
                      mid=self.rng.randint(-15, 15),
                      half=self.rng.randint(5, 40),
                      slope=self.rng.randint(0, 3),
                      invcoef=1,
                      inv=self.rng.randint(-50, 50),
                      maxqty=self.rng.choice([50, 100, 200, 500]),
                      expiry=10 ** 9, active=1, use_ref=1)

    @property
    def padded(self) -> int:
        return _pow2_ceil(self.n_makers)

    @property
    def reference(self) -> list[int]:
        return [a.reference for a in self.assets]

    # --- seats ---------------------------------------------------------------

    def new_session(self) -> str:
        return secrets.token_urlsafe(9)

    def claim(self, session: str, seat_id: str, label: str = "") -> tuple[bool, str]:
        if seat_id == OBSERVER:
            self.release(session)
            self.sessions[session] = OBSERVER
            return True, ""
        seat = self.seats.get(seat_id)
        if seat is None:
            return False, f"no seat called {seat_id}"
        if seat.holder is not None and seat.holder != session:
            return False, f"{seat_id} is taken by {seat.label or 'someone'}"
        self.release(session)
        seat.holder = session
        seat.label = label or seat.label
        self.sessions[session] = seat_id
        self.note(seat_id, "claimed", "info", seat=seat_id, label=seat.label)
        return True, ""

    def release(self, session: str) -> None:
        previous = self.sessions.pop(session, None)
        if previous and previous != OBSERVER:
            seat = self.seats.get(previous)
            if seat is not None and seat.holder == session:
                seat.holder = None

    def seat_of(self, session: str) -> Seat | None:
        seat_id = self.sessions.get(session)
        if seat_id in (None, OBSERVER):
            return None
        return self.seats.get(seat_id)

    def set_forced_manual(self, seat_id: str, forced: bool) -> None:
        seat = self.seats.get(seat_id)
        if seat is not None:
            seat.forced_manual = forced

    # --- what a seat does ----------------------------------------------------

    def set_policy(self, index: int, values: dict) -> None:
        policy = self.policies[index]
        for name in FIELDS:
            if name in values:
                setattr(policy, name, int(values[name]))
        policy.asset = max(0, min(policy.asset, len(self.assets) - 1))
        policy.maxqty = max(0, policy.maxqty)
        policy.half = max(0, policy.half)

    def set_behaviour(self, index: int, behaviour: str) -> None:
        if behaviour not in BEHAVIOURS:
            raise ValueError(f"unknown behaviour {behaviour}")
        self.behaviour[index] = behaviour

    def set_request(self, values: dict) -> None:
        for name in ("asset", "qty", "direction", "is_real"):
            if name in values:
                setattr(self.request, name, int(values[name]))
        self.request.asset = max(0, min(self.request.asset, len(self.assets) - 1))
        self.request.qty = max(1, self.request.qty)
        self.request.direction = SELL if self.request.direction else BUY

    def announce(self) -> None:
        """The taker telling the winner it won. Nothing else can tell it."""
        if self.last is None or self.last.outcome.winner is None:
            return
        self.last.announced = True
        winner = self.last.outcome.winner
        self.note(f"maker:{winner}", "you_won", "good", number=self.last.number)

    # --- notices -------------------------------------------------------------

    def note(self, seat_id: str, code: str, tone: str = "info", **fields) -> None:
        line = Notice(time.time(), code, fields, tone)
        self.notices.setdefault(seat_id, []).append(line)
        del self.notices[seat_id][:-40]

    def note_all(self, code: str, tone: str = "info", **fields) -> None:
        for seat_id in list(self.seats) + [OBSERVER]:
            self.note(seat_id, code, tone, **fields)

    # --- a round -------------------------------------------------------------

    def run_round(self) -> RoundResult:
        self.round_number += 1
        self.now_t += 1
        started = time.perf_counter()
        request = Request(asset=self.request.asset, qty=self.request.qty,
                          direction=self.request.direction,
                          entity=self.request.entity, is_real=self.request.is_real)
        policies = [Policy(**p.to_dict()) for p in self.policies]

        session = Session(self.n_nodes, self.threshold, dict(self.behaviour),
                          random.Random(self.rng.randrange(1 << 62)))
        verified, detail, stats = None, "", {}
        if self.engine is None:
            outcome, transcript, shares, used = self._compute(policies, request,
                                                              session)
        else:
            outcome, verified, detail, stats = self._compute_in_engine(
                policies, request, session)
            transcript, used = session.transcript, policies
            shares = stats.pop("shares", {})

        mask = self.rng.randrange(1 << 32)
        if outcome.winner is None or transcript.aborted:
            masked_key = self.rng.randrange(1 << 32)
        else:
            masked_key = outcome.cost * self.padded + outcome.winner + mask

        result = RoundResult(
            number=self.round_number, engine=getattr(self.engine, "name", "sim"),
            request=request, outcome=outcome, masked_key=masked_key, mask=mask,
            padded=self.padded, named=dict(transcript.named),
            rejected=[(r.node, r.dealer, r.position) for r in transcript.rejected],
            reductions=len(transcript.reductions),
            corrections=transcript.corrections, aborted=transcript.aborted,
            abort_reason=transcript.abort_reason,
            abort_code=transcript.abort_code,
            abort_fields=dict(transcript.abort_fields),
            product_capacity=transcript.product_capacity,
            open_capacity=transcript.open_capacity, silent=list(transcript.silent),
            corrupted_inputs=list(transcript.corrupted_inputs),
            input_check=self.input_check,
            ms=(time.perf_counter() - started) * 1e3, node_shares=shares,
            used_policies=[p.to_dict() for p in used],
            verified=verified, verified_detail=detail, engine_stats=stats)
        self.last = result
        self.history.append(result)
        del self.history[:-20]
        self._announce_round(result)
        return result

    def _compute(self, policies, request, session):
        """The round's arithmetic, and the shares each node held while doing it.

        The order is the deployment's order and it matters: values are dealt,
        the dealings are checked against what each node says it holds, and only
        then does anything get computed. A check that ran afterwards would be a
        check on an answer that is already out.

        Nothing here is told who cheated. The commitment check is handed the
        stated shares and the published commitments; the answer is computed from
        the sum of the stated shares, whatever they are. So a substituted input
        that nobody checked produces a wrong price by the same route it would in
        a deployment, rather than by this function deciding to be wrong.
        """
        reference = self.reference
        shares: dict[int, list[str]] = {}
        empty = Outcome()

        values = [request.asset, request.qty, request.direction, request.entity,
                  request.is_real]
        for policy in policies:
            values.extend(policy.as_fields())

        if not session.inputs_possible():
            return empty, session.transcript, shares, policies

        held = session.deal(values)
        stated, _ = session.substituted(held)
        for j in range(self.n_nodes):
            shares[j] = [f"{v & ((1 << 72) - 1):018x}" for v in stated[j][:6]]

        if self.input_check:
            started = time.perf_counter()
            rejected = self._check_dealings(held, stated, len(values))
            session.transcript.commit_ms = (time.perf_counter() - started) * 1e3
            if rejected:
                session.transcript.rejected = rejected
                culprits = sorted({r.node for r in rejected})
                who = ", ".join(f"node {j}" for j in culprits)
                session.transcript.stop(
                    "commitment",
                    f"{who} stated a share that does not open its commitment. "
                    f"Refused before computing, which is the only time refusing "
                    f"is worth anything.",
                    who=culprits)
                return empty, session.transcript, shares, policies

        # What the circuit computes on is the sum of what the nodes fed in, not
        # what the dealers meant. Reconstructing it here rather than reusing the
        # dealers' values is what makes an unchecked substitution show up as a
        # wrong answer instead of a correct one with a warning beside it.
        effective = [sum(stated[j][k] for j in range(self.n_nodes))
                     for k in range(len(values))]
        used_request = Request(asset=_clamp(effective[0], 0, len(self.assets) - 1),
                               qty=effective[1], direction=1 if effective[2] else 0,
                               entity=effective[3], is_real=1 if effective[4] else 0)
        used_policies = []
        for index in range(len(policies)):
            base = 5 + index * len(FIELDS)
            fields = dict(zip(FIELDS, effective[base:base + len(FIELDS)]))
            fields["asset"] = _clamp(fields["asset"], 0, len(self.assets) - 1)
            used_policies.append(Policy(**fields))
        outcome = evaluate(used_policies, used_request, reference, self.now_t)

        for index, policy in enumerate(used_policies):
            if session.transcript.aborted:
                break
            session.multiply(policy.slope, used_request.qty, f"maker {index} depth")
            if session.transcript.aborted:
                break
            session.multiply(policy.invcoef, policy.inv, f"maker {index} skew")
        if not session.transcript.aborted:
            session.open_value(outcome.cost or 0, "quote")
        return outcome, session.transcript, shares, used_policies

    def _compute_in_engine(self, policies, request, session):
        """Hand the whole round to MP-SPDZ and report what came back.

        The demo's own share layer does not run here. It would be a second
        story about the same round told beside the real one, and the node seats
        would end up showing shares that no process ever held. What a node is
        shown instead is its actual party file.

        The misbehaviour switches do not reach this engine and the round says
        so, rather than leaving a switch that looks connected and is not.
        """
        # A node seat that chose to lie during a multiplication is passed
        # through, so the switch corrupts a real party when the build can carry
        # it. `stats["robust"]` says whether it did, and the browser reads that
        # rather than assuming.
        lying = [j for j, b in self.behaviour.items() if b == LIE_PRODUCT]
        outcome, ok, detail, stats = self.engine.quote(
            request, policies, self.reference, self.now_t, corrupt=lying)
        if outcome is None:
            session.transcript.stop("engine", detail or "the engine did not answer")
            return Outcome(), False, detail, stats
        if not ok:
            # A disagreement between the circuit and the cleartext reference is
            # the one thing this engine exists to be able to notice, so it stops
            # the round rather than showing a number nothing vouched for.
            session.transcript.stop("mismatch", detail)
        named = stats.get("named") or []
        if named:
            session.transcript.name(named)
        # Only the switches the engine cannot carry are inert. Under the robust
        # build a wrong share in a multiplication is a real party misbehaving,
        # and the names above came out of its log.
        inert = [j for j, b in self.behaviour.items()
                 if b != HONEST and not (stats.get("robust") and b == LIE_PRODUCT)]
        if inert:
            session.transcript.inert_behaviours = inert
        return outcome, ok, detail, stats

    def _check_dealings(self, held, stated, n_values: int) -> list[Rejection]:
        """Every node's stated share against the commitment its dealer published.

        This is the check `BINDING.md` prices at `n` openings a value. It is
        exact --- a share that differs by one is caught --- and it is the only
        thing in the round that can see a substituted input, because a
        substituted input is a perfectly valid sharing of a different number and
        there is nothing else about it to notice.
        """
        rejected: list[Rejection] = []
        key = COMMIT_KEY
        for position in range(n_values):
            blindings = [key.random_blinding() for _ in range(self.n_nodes)]
            commitments = [key.commit(held[j][position], blindings[j])
                           for j in range(self.n_nodes)]
            # No commitment to the value itself. Under a hash it would not be
            # the product of the share commitments, so `Dealing.adds_up` could
            # not use it, and putting a digest there anyway would be a field
            # that looks like evidence and is not.
            dealing = Dealing(value_commitment=None,
                              share_commitments=commitments)
            for j in range(self.n_nodes):
                if not check_share(key, dealing, j, stated[j][position], blindings[j]):
                    rejected.append(Rejection(node=j, dealer=_dealer_of(position),
                                              position=position))
        return rejected

    def _announce_round(self, result: RoundResult) -> None:
        if result.aborted:
            self.note_all("stopped", "bad", number=result.number,
                          why=result.abort_code, detail=result.abort_reason,
                          **result.abort_fields)
        elif result.corrections:
            self.note_all("corrected", "warn", number=result.number,
                          corrections=result.corrections,
                          reductions=result.reductions,
                          named=sorted(result.named))
        else:
            self.note_all("finished", "info", number=result.number,
                          real=bool(result.request.is_real))
        if result.rejected:
            self.note_all("refused", "bad",
                          who=sorted({n for n, _, _ in result.rejected}))
        elif result.corrupted_inputs and not result.input_check:
            self.note_all("unchecked", "bad", who=result.corrupted_inputs)
