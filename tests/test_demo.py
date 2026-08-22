"""The demo, tested where it could be wrong in a way that matters.

Two kinds of claim are worth a test here and the rest is not. The first is that
the market the demo prices is the market the circuit prices --- if those drift,
every round on screen is a demonstration of something else, and the drift would
be silent. The second is that a seat is told only its own business, because that
separation *is* the demonstration, and a projection that leaked would leave the
demo showing the opposite of what it claims while looking identical.

The behaviour table is here too. It is the same table that was measured against
MP-SPDZ at `n = 9`, `T = 2`, and having it run in a second every commit is what
keeps the browser's version honest about the engine's.
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "mp_spdz"))

from qomm_demo import model                                       # noqa: E402
from qomm_demo.model import BUY, FIELDS, SELL, Policy, Request    # noqa: E402
from qomm_demo.protocol import (DROPOUT, LIE_INPUT, LIE_OPEN,     # noqa: E402
                                LIE_PRODUCT, OFFLINE, Session)
from qomm_demo.room import Room                                   # noqa: E402
from qomm_demo.server import Demo                                 # noqa: E402
from qomm_demo.wsserver import (Server, frame, http_reply,        # noqa: E402
                                parse_query, unquote)


# --- the market is the circuit's market ----------------------------------

def _fixture(rng, n_assets=3):
    policies = [Policy(asset=rng.randrange(n_assets), mid=rng.randint(-15, 15),
                       half=rng.randint(5, 40), slope=rng.randint(0, 3),
                       invcoef=rng.randint(0, 2), inv=rng.randint(-50, 50),
                       maxqty=rng.choice([50, 100, 200, 500]),
                       expiry=rng.choice([0, 10 ** 9]),
                       active=rng.choice([0, 1, 1, 1]), use_ref=1)
                for _ in range(8)]
    request = Request(asset=rng.randrange(n_assets),
                      qty=rng.choice([10, 50, 100, 200, 400]),
                      direction=rng.choice([BUY, SELL]))
    return policies, request


@pytest.mark.parametrize("seed", range(25))
def test_the_demo_prices_what_the_circuit_prices(seed):
    """`qomm_demo.model` against the generator's own cleartext reference.

    The generator computes this as a side effect of emitting a party fixture,
    which is why the demo has its own copy. This is the check that keeps the
    copy a copy.
    """
    from gen_qomm import build_inputs

    rng = random.Random(seed)
    reference_prices = [15750, 10850, 6420000]
    policies, request = _fixture(rng)
    _, generated = build_inputs(
        n_mm=8, n_real_mm=8, n_parties=7, is_real=1, n_requests=1, n_assets=3,
        ref_table=reference_prices, user_asset=request.asset,
        user_qty=request.qty, user_dir=request.direction, user_entity=0,
        now_t=1, ref_mid=0, seed=seed,
        policies_in=[dict(zip(FIELDS, p.as_fields())) for p in policies])
    ours = model.evaluate(policies, request, reference_prices, now_t=1)

    assert ours.winner == generated["best_mm"]
    assert ours.cost == generated["best_cost"]
    assert ours.eligible == generated["eligible_count"]
    assert [(q.ask, q.bid) for q in ours.quotes] == \
        [(q["ask"], q["bid"]) for q in generated["quotes"]]


def test_selling_maximises_the_bid_and_buying_minimises_the_ask():
    """One tournament serves both directions, which is why cost is negated."""
    policies = [Policy(mid=0, half=10, slope=0, invcoef=0, inv=0),
                Policy(mid=0, half=30, slope=0, invcoef=0, inv=0)]
    reference = [1000]
    buying = model.evaluate(policies, Request(qty=1, direction=BUY), reference, 0)
    selling = model.evaluate(policies, Request(qty=1, direction=SELL), reference, 0)
    assert buying.winner == 0 and buying.price == 1010     # the tighter ask
    assert selling.winner == 0 and selling.price == 990    # the higher bid


# --- what a seat is told --------------------------------------------------

def _room_with_seats():
    demo = Demo(Room(seed=4), step_ms=0)
    demo.room.claim("t", "taker", "Ann")
    demo.room.claim("m", "maker:2", "Bo")
    demo.room.claim("n", "node:4", "Rin")
    demo.room.claim("o", "observer")
    return demo


def test_a_node_is_not_told_the_price_or_the_order():
    demo = _room_with_seats()
    result = demo.room.run_round()
    blob = json.dumps(demo.view("n"))
    assert result.outcome.price is not None
    assert str(result.outcome.price) not in blob
    assert str(result.request.qty) not in blob.replace(
        str(result.number), "")            # the round number is not the size
    assert str(result.mask) not in blob
    assert "policy" not in blob


def test_a_maker_is_told_its_own_policy_and_no_other():
    demo = _room_with_seats()
    demo.room.set_policy(2, {"mid": 7, "half": 33})
    demo.room.set_policy(5, {"mid": -21, "half": 44})
    demo.room.run_round()
    view = demo.view("m")
    assert view["maker"]["policy"]["mid"] == 7
    blob = json.dumps(view)
    assert "-21" not in blob and '"half": 44' not in blob


def test_a_maker_learns_it_won_only_when_the_taker_says_so():
    """The opened key is masked, so nothing else can tell a maker anything."""
    demo = Demo(Room(seed=11), step_ms=0)
    demo.room.claim("m", "maker:0")
    # every seat held, so no bot moves anything and maker 0 is the only one
    # that can win --- the point being tested is the telling, not the winning
    for index in range(demo.room.n_makers):
        demo.room.claim(f"h{index}", f"maker:{index}")
        demo.room.set_policy(index, {"active": 0 if index else 1, "asset": 0,
                                     "maxqty": 500})
    demo.room.claim("m", "maker:0")
    demo.room.claim("t", "taker")
    demo.room.set_request({"asset": 0, "qty": 100, "is_real": 1})
    result = demo.room.run_round()
    assert result.outcome.winner == 0
    assert demo.view("m")["maker"]["fill"] is None
    demo.room.announce()
    assert demo.view("m")["maker"]["fill"]["price"] == result.outcome.price


def test_a_node_behaviour_is_visible_to_that_node_and_the_observer_only():
    demo = _room_with_seats()
    demo.room.set_behaviour(4, LIE_PRODUCT)
    mine = [s for s in demo.view("n")["seats"] if "behaviour" in s]
    assert [s["id"] for s in mine] == ["node:4"]
    assert not [s for s in demo.view("t")["seats"] if "behaviour" in s]
    assert len([s for s in demo.view("o")["seats"] if "behaviour" in s]) == 9


def test_the_taker_alone_can_unpack_the_opened_key():
    demo = _room_with_seats()
    result = demo.room.run_round()
    cost, maker = result.unpack()
    assert (cost, maker) == (result.outcome.cost, result.outcome.winner)
    # everyone sees the same number and it is not the price
    assert demo.view("n")["public"]["masked_key"] == str(result.masked_key)
    assert result.masked_key != result.outcome.cost


# --- seats ---------------------------------------------------------------

def test_a_seat_cannot_be_taken_twice_and_comes_back_when_released():
    room = Room(seed=1)
    assert room.claim("a", "node:0", "Ann")[0]
    ok, why = room.claim("b", "node:0", "Bo")
    assert not ok and "Ann" in why
    assert room.seats["node:0"].mode == "manual"
    room.release("a")
    assert room.seats["node:0"].mode == "auto"
    assert room.claim("b", "node:0", "Bo")[0]


def test_claiming_a_second_seat_gives_up_the_first():
    room = Room(seed=1)
    room.claim("a", "maker:1")
    room.claim("a", "node:2")
    assert room.seats["maker:1"].holder is None
    assert room.seats["node:2"].holder == "a"


# --- the behaviour table, the same one the engine was measured on ---------

def _round(behaviours, input_check=True, seed=1):
    room = Room(seed=seed, input_check=input_check)
    for index, behaviour in behaviours.items():
        room.set_behaviour(index, behaviour)
    return room.run_round()


def test_nine_nodes_and_a_threshold_of_two_correct_two_liars_and_name_them():
    honest = _round({})
    for liars in ([0], [0, 4], [8]):
        result = _round({j: LIE_PRODUCT for j in liars})
        assert not result.aborted
        assert sorted(result.named) == sorted(liars)
        assert result.outcome.price == honest.outcome.price
        assert result.outcome.winner == honest.outcome.winner


def test_a_third_liar_is_beyond_the_capacity_and_the_round_says_so():
    result = _round({0: LIE_PRODUCT, 4: LIE_PRODUCT, 7: LIE_PRODUCT})
    assert result.aborted and result.abort_code == "beyond_capacity"
    assert result.abort_fields["capacity"] == 2
    assert not result.named


def test_a_dropout_costs_decoding_capacity():
    """Eight answering nodes at degree four correct one, not two."""
    two = _round({0: LIE_PRODUCT, 1: LIE_PRODUCT})
    assert not two.aborted
    with_dropout = _round({3: DROPOUT, 0: LIE_PRODUCT, 1: LIE_PRODUCT})
    assert with_dropout.aborted
    assert with_dropout.abort_fields["capacity"] == 1
    assert with_dropout.abort_fields["answered"] == 8


def test_a_node_that_never_turns_up_takes_the_input_phase_with_it():
    result = _round({2: OFFLINE})
    assert result.aborted and result.abort_code == "absent"
    assert result.reductions == 0


def test_the_opening_corrects_more_than_the_products_do():
    result = _round({1: LIE_OPEN, 5: LIE_OPEN, 6: LIE_OPEN})
    assert not result.aborted
    assert sorted(result.named) == [1, 5, 6]
    assert result.open_capacity == 3 and result.product_capacity == 2


def test_a_substituted_input_is_caught_by_the_commitment_and_by_nothing_else():
    checked = _round({5: LIE_INPUT}, input_check=True)
    assert checked.aborted and checked.abort_code == "commitment"
    assert [r[0] for r in checked.rejected] == [5]

    unchecked = _round({5: LIE_INPUT}, input_check=False)
    assert not unchecked.aborted
    assert not unchecked.named and not unchecked.rejected
    # nothing was inconsistent, so the round finished --- with the wrong answer
    assert unchecked.outcome.price != _round({}).outcome.price


def test_the_decoder_never_names_an_innocent_node():
    """Across many rounds and many liars, the named set is exactly the liars."""
    rng = random.Random(3)
    for _ in range(40):
        liars = rng.sample(range(9), rng.randint(0, 2))
        result = _round({j: LIE_PRODUCT for j in liars}, seed=rng.randrange(1000))
        assert sorted(result.named) == sorted(liars)


def test_a_session_refuses_a_threshold_its_node_count_cannot_carry():
    with pytest.raises(ValueError, match="cannot carry"):
        Session(4, 2, {})


# --- the wire ------------------------------------------------------------

def test_a_frame_is_read_back_as_it_was_written():
    import asyncio

    from qomm_demo.wsserver import TEXT, read_frame

    def masked_frame(payload: bytes) -> bytes:
        """What a browser would put on the wire. All three length forms."""
        size = len(payload)
        head = bytes([0x80 | TEXT])
        if size < 126:
            head += bytes([0x80 | size])
        elif size < (1 << 16):
            head += bytes([0x80 | 126]) + size.to_bytes(2, "big")
        else:
            head += bytes([0x80 | 127]) + size.to_bytes(8, "big")
        key = b"\x01\x02\x03\x04"
        return head + key + bytes(c ^ key[i & 3] for i, c in enumerate(payload))

    async def go(payload: bytes):
        reader = asyncio.StreamReader()
        reader.feed_data(masked_frame(payload))
        reader.feed_eof()
        return await read_frame(reader)

    for payload in (b"{}", b"x" * 200, b"y" * 70000):
        opcode, got = asyncio.run(go(payload))
        assert opcode == TEXT and got == payload


def test_a_path_that_climbs_out_of_the_static_directory_is_refused(tmp_path):
    import asyncio

    class Sink:
        def __init__(self):
            self.out = b""

        def write(self, data):
            self.out += data

        async def drain(self):
            pass

    server = Server(ROOT / "qomm_demo" / "static", None, None, None)
    for path in ("/../../../etc/passwd", "/..%2f..%2fsecret", "/nope.js"):
        sink = Sink()
        asyncio.run(server._serve_file(path, sink))
        assert b"404" in sink.out
    sink = Sink()
    asyncio.run(server._serve_file("/demo.js", sink))
    assert b"200 OK" in sink.out


def test_query_parsing_handles_what_a_seat_link_carries():
    # a label with a multi-byte character in it, because seat links get pasted
    # into chat by people whose names have them
    assert parse_query("seat=node%3A3&label=Ann%C3%A9") == \
        {"seat": "node:3", "label": "Ann\u00e9"}
    assert parse_query("") == {}
    assert unquote("a+b") == "a b"


def test_the_reply_tells_a_browser_not_to_cache_the_page():
    """A cached page holds a seat with stale code, which is unexplainable live."""
    assert b"Cache-Control: no-store" in http_reply("200 OK", b"x", "text/html")
