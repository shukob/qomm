"""What an unclaimed seat does, so a demo can be given by one person.

Every seat has a behaviour whether or not somebody is in it. The bots are
deliberately small: a maker that reacts to having been filled, a taker that
sends a mix of live orders and cover, and nodes that are honest until someone
sits down and decides otherwise. Nothing here tries to be a market simulation
--- `qomm_sim` is that, with tapes and attackers and an evaluation harness. This
is only enough motion that a screen left alone still shows something happening.

The one behaviour worth calling out is the maker's inventory. A maker that wins
has traded, so its position moves, so its skew moves, so its next quote is worse
on the side it just traded --- and the next round a different maker wins. Quote
rotation falls out of that rather than being scripted, and watching it happen is
a better argument that the tournament is doing something than any caption.
"""

from __future__ import annotations

import random

from .model import BUY, SELL, Policy, Request


class MakerBot:
    """One automatic maker. Drifts, and reacts to being filled."""

    def __init__(self, index: int, rng: random.Random):
        self.index = index
        self.rng = rng

    def step(self, policy: Policy, n_assets: int) -> None:
        policy.mid += self.rng.randint(-2, 2)
        policy.mid = max(-40, min(40, policy.mid))
        # a spread that only ever wandered would end up at one extreme, so it
        # is pulled back towards where it started
        policy.half += self.rng.randint(-3, 3) + (1 if policy.half < 8 else 0) \
            - (1 if policy.half > 45 else 0)
        policy.half = max(3, min(60, policy.half))
        policy.inv = max(-120, min(120, policy.inv + self.rng.randint(-4, 4)))
        if self.rng.random() < 0.04:
            policy.active = 1 if policy.active == 0 else self.rng.choice([0, 1, 1, 1])
        if self.rng.random() < 0.05:
            policy.asset = self.rng.randrange(n_assets)

    def filled(self, policy: Policy, request: Request) -> None:
        """The taker bought from it, or sold to it. Either way its book moved."""
        moved = max(1, request.qty // 8)
        # the taker buying means this maker sold, which leaves it short and
        # wanting to buy back: both its quotes lift
        policy.inv += moved if request.direction == BUY else -moved
        policy.inv = max(-120, min(120, policy.inv))


class TakerBot:
    """One automatic taker. Sends cover as well as orders, and does not say which."""

    def __init__(self, rng: random.Random, cover_rate: float = 0.35):
        self.rng = rng
        self.cover_rate = cover_rate

    def step(self, request: Request, n_assets: int) -> None:
        request.asset = self.rng.randrange(n_assets)
        request.qty = self.rng.choice([10, 25, 50, 100, 100, 150, 200, 400])
        request.direction = self.rng.choice([BUY, SELL])
        request.is_real = 0 if self.rng.random() < self.cover_rate else 1
