"""The market the demo is a demonstration of, in the clear.

This is the same arithmetic `mp_spdz/gen_qomm.py` writes into its cleartext
reference --- the thing the compiled circuit is checked against. It is repeated
here rather than imported because the generator computes it as a side effect of
emitting inputs for a particular fixture, and the demo needs it as a function of
policies a person is editing in a browser. `tests/test_demo_model.py` runs both
on the same fixtures and requires them to agree, so the repetition is checked
rather than trusted.

A quote is a straight line in the order's size, anchored on a public reference
price and shifted by what the maker holds:

    anchor = use_ref * reference[asset] + mid
    ask    = anchor + half + slope*qty + invcoef*inv
    bid    = anchor - half - slope*qty + invcoef*inv

`half` is the half-spread, `slope*qty` is how much the maker charges for size,
and `invcoef*inv` slides both sides together rather than widening them. The sign
convention is the one the generator already emits and is worth stating plainly,
because it is the opposite of what the word "inventory" suggests at a glance:
the skew is *added*, so a positive `inv` lifts both quotes --- the posture of a
maker that has sold too much and wants to buy it back --- and a negative one
drops both, which is a maker that is long and wants to sell. A maker is eligible
if it makes a market in the asset asked for, will take a size that large, is
switched on, and has not expired.

The taker's cost is the ask when buying and the negated bid when selling, so one
minimisation serves both directions --- which is why the circuit has one
tournament and not two.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

# The order the generator deals a policy in. Kept identical so a policy edited
# in a browser can be handed to the real circuit without a translation step.
FIELDS = ("asset", "mid", "half", "slope", "invcoef", "inv", "maxqty",
          "expiry", "active", "use_ref")

BUY, SELL = 0, 1


@dataclass
class Policy:
    """One maker's price curve. Every field is secret to that maker."""

    asset: int = 0
    mid: int = 0            # offset from the public reference
    half: int = 20          # half-spread
    slope: int = 1          # charge per unit of size
    invcoef: int = 1        # how hard the skew pushes the curve
    inv: int = 0            # skew: positive lifts both quotes, negative drops them
    maxqty: int = 200       # largest order this maker will price
    expiry: int = 10**9     # the round after which this policy is stale
    active: int = 1
    use_ref: int = 1        # 0 for a maker that prices without the reference

    def as_fields(self) -> list[int]:
        return [int(getattr(self, name)) for name in FIELDS]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Request:
    """What a taker asks. Every field is secret to the taker.

    `is_real` is the one that matters most and is easiest to overlook: a cover
    request runs the identical circuit, moves the identical bytes and takes the
    identical time. Nothing outside the taker's own seat can tell the two apart,
    which is the property the fixed-size frames and the fixed schedule exist to
    protect.
    """

    asset: int = 0
    qty: int = 100
    direction: int = BUY
    entity: int = 0
    is_real: int = 1


@dataclass
class Quote:
    maker: int
    ask: int
    bid: int
    eligible: bool
    reason: str = ""
    cost: int | None = None


@dataclass
class Outcome:
    """What the round computed, in full. No seat is shown all of it."""

    quotes: list[Quote] = field(default_factory=list)
    winner: int | None = None
    price: int | None = None        # signed the way the taker experiences it
    cost: int | None = None         # what the tournament minimised
    eligible: int = 0

    @property
    def none_eligible(self) -> bool:
        return self.winner is None


def price_one(policy: Policy, request: Request, reference: list[int]) -> tuple[int, int]:
    """The two sides this maker would show for this order."""
    anchor = policy.use_ref * reference[request.asset] + policy.mid
    depth = policy.slope * request.qty
    skew = policy.invcoef * policy.inv
    return (anchor + policy.half + depth + skew,      # ask
            anchor - policy.half - depth + skew)      # bid


def ineligible_reason(policy: Policy, request: Request, now_t: int) -> str:
    """Why this maker is out, in the order a person would check.

    Only the maker's own seat is ever shown this. It is derived from that
    maker's own policy and the order it did not get, so telling it costs
    nothing --- and a maker that never learns *why* it stopped winning will
    quietly stay switched off, which is the failure mode of every quiet system.
    """
    if not policy.active:
        return "switched off"
    if policy.asset != request.asset:
        return "different market"
    if request.qty > policy.maxqty:
        return f"size {request.qty} above its limit {policy.maxqty}"
    if policy.expiry <= now_t:
        return "policy expired"
    return ""


def evaluate(policies: list[Policy], request: Request, reference: list[int],
             now_t: int) -> Outcome:
    """Every quote, and the one the tournament would pick."""
    out = Outcome()
    best_cost: int | None = None
    for index, policy in enumerate(policies):
        ask, bid = price_one(policy, request, reference)
        reason = ineligible_reason(policy, request, now_t)
        cost = -bid if request.direction == SELL else ask
        quote = Quote(maker=index, ask=ask, bid=bid, eligible=not reason,
                      reason=reason, cost=cost if not reason else None)
        out.quotes.append(quote)
        if reason:
            continue
        out.eligible += 1
        if best_cost is None or cost < best_cost:
            best_cost, out.winner = cost, index
    out.cost = best_cost
    if best_cost is not None:
        out.price = -best_cost if request.direction == SELL else best_cost
    return out
