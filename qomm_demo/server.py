"""The loop, and the projection that decides what each browser is told.

`view` is the part to read. A round is computed once, in full, and then each
connection is handed a dictionary built from scratch for its seat. Nothing is
sent and hidden; what a seat is not entitled to never reaches it, so a person
with the developer console open learns exactly what a person without one does.

Three things are worth saying about what is entitled to what.

A **node's chosen behaviour is private to that node.** In a deployment nobody
announces that they are about to cheat, and a demo that showed the switch to the
room would be showing the answer before the question. What becomes public is
what the protocol itself produces: the count of corrected openings and the
indices it named.

A **maker never sees the order.** It sets a policy and the policy is priced
against something it is not shown, which is the whole arrangement. It cannot
even be told whether it was eligible, because eligibility is a fact about the
order. What it learns is whether it won, and it learns that from the taker.

The **taker holds the mask**, so the taker alone turns the opened key into a
price and a winner. Everyone else sees the same uniform number.
"""

from __future__ import annotations

import asyncio
import json
import random
import time
from pathlib import Path

from .bots import MakerBot, TakerBot
from .model import FIELDS
from .protocol import BEHAVIOURS, HONEST
from .room import MAKER, NODE, OBSERVER, TAKER, Room
from .wsserver import Connection, Server, lan_addresses

STATIC = Path(__file__).resolve().parent / "static"

SIM_NOTE = "share layer real, tournament in the clear"


class Demo:
    def __init__(self, room: Room, engine=None, round_seconds: float = 6.0,
                 step_ms: int = 350, auto_rounds: bool = True,
                 seed: int | None = None):
        self.room = room
        self.engine = engine
        self.round_seconds = round_seconds
        self.step_ms = step_ms
        self.auto_rounds = auto_rounds
        self.connections: dict[str, Connection] = {}
        self.rng = random.Random(seed)
        self.maker_bots = [MakerBot(i, self.rng) for i in range(room.n_makers)]
        self.taker_bot = TakerBot(self.rng)
        self.phase = "idle"
        self.phase_note = ""
        self.next_round_at = time.time() + round_seconds
        self.busy = False
        self.server = Server(STATIC, self.on_open, self.on_message, self.on_close)

    # --- connections ---------------------------------------------------------

    async def on_open(self, connection: Connection) -> None:
        connection.session = (connection.query.get("session")
                              or self.room.new_session())
        self.connections[connection.session] = connection
        seat = connection.query.get("seat")
        label = connection.query.get("label", "")
        if seat:
            self.room.claim(connection.session, seat, label)
        await self.send_view(connection)

    async def on_close(self, connection: Connection) -> None:
        self.connections.pop(connection.session, None)
        # The seat goes back to automatic. A person who closed a laptop should
        # not be able to stall the room by having held a seat.
        self.room.release(connection.session)
        await self.broadcast()

    async def on_message(self, connection: Connection, message: dict) -> None:
        kind = message.get("type")
        session = connection.session
        seat = self.room.seat_of(session)
        watching = self.room.sessions.get(session) == OBSERVER

        if kind == "claim":
            ok, why = self.room.claim(session, str(message.get("seat", "")),
                                      str(message.get("label", ""))[:24])
            if not ok:
                await connection.send({"type": "refused", "reason": why})
        elif kind == "release":
            self.room.release(session)
        elif kind == "policy" and seat and seat.kind == MAKER:
            self.room.set_policy(seat.index, message.get("values", {}))
        elif kind == "behaviour" and seat and seat.kind == NODE:
            value = str(message.get("value", HONEST))
            if value in BEHAVIOURS:
                self.room.set_behaviour(seat.index, value)
        elif kind == "request" and seat and seat.kind == TAKER:
            self.room.set_request(message.get("values", {}))
        elif kind == "submit" and seat and seat.kind == TAKER:
            await self.play_round(triggered_by="the taker")
            return
        elif kind == "submit_any" and watching:
            await self.play_round(triggered_by="the room")
            return
        elif kind == "announce" and seat and seat.kind == TAKER:
            self.room.announce()
        elif kind == "config" and (watching or seat is None or seat.kind == TAKER):
            self.configure(message.get("values", {}))
        elif kind == "force":
            self.room.set_forced_manual(str(message.get("seat", "")),
                                        bool(message.get("manual")))
        await self.broadcast()

    def configure(self, values: dict) -> None:
        if "round_seconds" in values:
            self.round_seconds = max(1.0, min(120.0, float(values["round_seconds"])))
            self.next_round_at = time.time() + self.round_seconds
        if "step_ms" in values:
            self.step_ms = max(0, min(2000, int(values["step_ms"])))
        if "auto_rounds" in values:
            self.auto_rounds = bool(values["auto_rounds"])
        if "input_check" in values:
            self.room.input_check = bool(values["input_check"])

    # --- rounds --------------------------------------------------------------

    async def play_round(self, triggered_by: str) -> None:
        """One round, then a walk through what it did, slowly enough to watch.

        The round is computed first and the phases are a replay of it. Doing it
        the other way --- pausing between real steps --- would make the pauses
        look like protocol time, and they are not: the arithmetic takes a couple
        of milliseconds and the view reports that separately from the pacing.
        """
        if self.busy:
            return
        self.busy = True
        try:
            self.step_bots()
            result = await asyncio.get_running_loop().run_in_executor(
                None, self.room.run_round)
            for phase, note in self.phases_of(result):
                self.phase, self.phase_note = phase, note
                await self.broadcast()
                if self.step_ms:
                    await asyncio.sleep(self.step_ms / 1000)
            self.phase = "done"
            self.phase_note = f"round {result.number}, started by {triggered_by}"
            self.settle(result)
            self.next_round_at = time.time() + self.round_seconds
        finally:
            self.busy = False
        await self.broadcast()

    def phases_of(self, result) -> list[tuple[str, str]]:
        """The steps the round went through, each captioned with what happened."""
        room = self.room
        n_values = 5 + room.n_makers * len(FIELDS)
        steps = [("deal", f"{n_values} values split into {room.n_nodes} shares "
                          f"each, one share per node")]
        if result.aborted and not result.rejected and not result.reductions:
            steps.append(("check", result.abort_reason))
            return steps
        if room.input_check:
            caption = (f"{n_values} x {room.n_nodes} shares against the "
                       f"commitments they were dealt under")
            if result.rejected:
                caption = result.abort_reason
            steps.append(("check", caption))
        else:
            steps.append(("check", "skipped: nothing binds a node to the share "
                                   "it was dealt"))
        if result.aborted and result.rejected:
            return steps
        reduce_note = (f"{result.reductions} products opened at degree "
                       f"{2 * room.threshold} and decoded")
        if result.corrections:
            named = ", ".join(f"node {j}" for j in sorted(result.named))
            reduce_note += f"; corrected {result.corrections}, named {named}"
        elif result.aborted:
            reduce_note = result.abort_reason
        steps.append(("reduce", reduce_note))
        if not result.aborted:
            steps.append(("open", "the key opens under the taker's mask; only "
                                  "the taker can subtract it"))
        return steps

    def step_bots(self) -> None:
        """Every seat nobody is sitting in decides what it wants this round."""
        for index, bot in enumerate(self.maker_bots):
            if not self.room.seats[f"maker:{index}"].manual:
                bot.step(self.room.policies[index], len(self.room.assets))
        if not self.room.seats["taker"].manual:
            self.taker_bot.step(self.room.request, len(self.room.assets))

    def settle(self, result) -> None:
        """The winner's book moves, and an automatic taker tells it that it won."""
        winner = result.outcome.winner
        if winner is None or result.aborted or not result.request.is_real:
            return
        if not self.room.seats[f"maker:{winner}"].manual:
            self.maker_bots[winner].filled(self.room.policies[winner],
                                           result.request)
        if not self.room.seats["taker"].manual:
            self.room.announce()

    async def ticker(self) -> None:
        """Start rounds on the clock, and keep the countdown honest.

        Once a second rather than continuously: the only thing that changes
        between rounds is the countdown, and a browser redrawing itself several
        times a second is a browser nobody can scroll.
        """
        while True:
            await asyncio.sleep(0.5)
            # A person sitting in the taker seat is the one who decides when to
            # ask, which is what a request-for-quote is. The clock keeps the
            # room moving only while nobody is doing that; the observer can
            # still force a round either way.
            waiting_on_a_person = self.room.seats["taker"].manual
            if (self.auto_rounds and not waiting_on_a_person and not self.busy
                    and time.time() >= self.next_round_at):
                await self.play_round(triggered_by="the clock")
            elif not self.busy:
                await self.broadcast()

    # --- what each seat is told ----------------------------------------------

    def view(self, session: str) -> dict:
        room = self.room
        seat = room.seat_of(session)
        seat_id = room.sessions.get(session)
        watching = seat_id == OBSERVER
        result = room.last

        payload = {
            "type": "view",
            "session": session,
            "seat": seat_id,
            "kind": seat.kind if seat else (OBSERVER if watching else None),
            "index": seat.index if seat else None,
            "label": seat.label if seat else "",
            "config": {
                "n_makers": room.n_makers, "n_nodes": room.n_nodes,
                "threshold": room.threshold, "input_check": room.input_check,
                "round_seconds": self.round_seconds, "step_ms": self.step_ms,
                "auto_rounds": self.auto_rounds,
                "engine": getattr(self.engine, "name", "sim"),
                "engine_note": getattr(self.engine, "note", SIM_NOTE),
            "robust": getattr(self.engine, "robust", True),
            "robust_reason": getattr(self.engine, "robust_reason", ""),
            },
            "assets": [{"name": a.name, "reference": a.reference, "scale": a.scale}
                       for a in room.assets],
            "phase": self.phase, "phase_note": self.phase_note,
            "next_round_in": (max(0.0, self.next_round_at - time.time())
                              if not room.seats["taker"].manual else None),
            "seats": [self.seat_summary(s, session) for s in room.seats.values()],
            "notices": [{"at": n.at, "code": n.code, "fields": n.fields,
                         "tone": n.tone}
                        for n in room.notices.get(seat_id or OBSERVER, [])[-12:]],
            "public": self.public(result),
            "history": [self.public(r) for r in room.history[-8:]],
        }
        if seat and seat.kind == TAKER:
            payload["taker"] = self.taker_view(result)
        if seat and seat.kind == MAKER:
            payload["maker"] = self.maker_view(seat.index, result)
        if seat and seat.kind == NODE:
            payload["node"] = self.node_view(seat.index, result)
        if watching:
            payload["observer"] = self.observer_view(result)
        return payload

    def seat_summary(self, seat, session: str) -> dict:
        """Who is where. A node's chosen behaviour is not part of this."""
        mine = seat.holder == session
        out = {"id": seat.id, "kind": seat.kind, "index": seat.index,
               "mode": seat.mode, "held": seat.holder is not None,
               "label": seat.label if seat.holder else "", "mine": mine,
               "forced_manual": seat.forced_manual}
        if seat.kind == NODE and (mine or self.room.sessions.get(session) == OBSERVER):
            out["behaviour"] = self.room.behaviour[seat.index]
        return out

    def public(self, result) -> dict:
        """What a transcript posted to the room would say. No prices in it."""
        if result is None:
            return {}
        return {
            "number": result.number, "engine": result.engine,
            "masked_key": str(result.masked_key),
            "reductions": result.reductions, "corrections": result.corrections,
            "named": sorted(result.named), "named_counts": {str(k): v for k, v
                                                            in result.named.items()},
            "aborted": result.aborted, "abort_reason": result.abort_reason,
            "abort_code": result.abort_code, "abort_fields": result.abort_fields,
            "product_capacity": result.product_capacity,
            "open_capacity": result.open_capacity,
            "silent": result.silent,
            "rejected": [{"node": n, "dealer": d, "position": p}
                         for n, d, p in result.rejected],
            "ms": round(result.ms, 1),
            "verified": result.verified, "verified_detail": result.verified_detail,
            "engine_stats": result.engine_stats,
            "inert": bool(result.engine_stats),
        }

    def taker_view(self, result) -> dict:
        request = self.room.request
        out = {"pending": {"asset": request.asset, "qty": request.qty,
                           "direction": request.direction,
                           "is_real": request.is_real}}
        if result is None:
            return out
        cost, maker = result.unpack()
        out["last"] = {
            "number": result.number,
            "asset": result.request.asset, "qty": result.request.qty,
            "direction": result.request.direction, "is_real": result.request.is_real,
            "mask": str(result.mask),
            "price": result.outcome.price, "winner": result.outcome.winner,
            "unpacked_cost": cost, "unpacked_maker": maker,
            "eligible": result.outcome.eligible, "announced": result.announced,
        }
        return out

    def maker_view(self, index: int, result) -> dict:
        """This maker's own policy, and a fill only when the taker said so."""
        out = {"policy": self.room.policies[index].to_dict(), "fields": list(FIELDS)}
        if result is None:
            return out
        won = (result.outcome.winner == index and result.announced
               and not result.aborted)
        out["fill"] = None
        if won:
            out["fill"] = {
                "number": result.number, "asset": result.request.asset,
                "qty": result.request.qty, "direction": result.request.direction,
                "price": result.outcome.price,
            }
        out["told_nothing"] = not won
        return out

    def node_view(self, index: int, result) -> dict:
        out = {"behaviour": self.room.behaviour[index], "shares": [],
               "named_me": False, "times_named": 0}
        if result is None:
            return out
        out["shares"] = result.node_shares.get(index, [])
        out["times_named"] = result.named.get(index, 0)
        out["named_me"] = out["times_named"] > 0
        out["rejected_me"] = any(n == index for n, _, _ in result.rejected)
        out["silent_me"] = index in result.silent
        return out

    def observer_view(self, result) -> dict:
        out = {"behaviours": {str(j): b for j, b in self.room.behaviour.items()},
               "policies": [p.to_dict() for p in self.room.policies]}
        if result is None:
            return out
        out["request"] = {"asset": result.request.asset, "qty": result.request.qty,
                          "direction": result.request.direction,
                          "is_real": result.request.is_real}
        out["price"] = result.outcome.price
        out["winner"] = result.outcome.winner
        out["eligible"] = result.outcome.eligible
        out["mask"] = str(result.mask)
        # Each row carries the market its own maker was in at the time, so the
        # table stands on its own rather than needing to be joined against a
        # list that has moved on since.
        out["quotes"] = [{"maker": q.maker, "ask": q.ask, "bid": q.bid,
                          "eligible": q.eligible, "reason": q.reason,
                          "asset": (result.used_policies[q.maker]["asset"]
                                    if q.maker < len(result.used_policies) else 0)}
                         for q in result.outcome.quotes]
        return out

    # --- sending -------------------------------------------------------------

    async def send_view(self, connection: Connection) -> None:
        await connection.send(self.view(connection.session))

    async def broadcast(self) -> None:
        for connection in list(self.connections.values()):
            if connection.open:
                await self.send_view(connection)
            else:
                self.connections.pop(connection.session, None)

    async def serve(self, host: str, port: int) -> None:
        server = await asyncio.start_server(self.server.handle, host, port)
        for url in lan_addresses(port):
            print(f"  {url}", flush=True)
        print(f"  seats: taker, maker:0..{self.room.n_makers - 1}, "
              f"node:0..{self.room.n_nodes - 1}, observer", flush=True)
        asyncio.create_task(self.ticker())
        async with server:
            await server.serve_forever()
