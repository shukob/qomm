"""No computing node holds a whole request or a whole policy.

This is the property the design has always claimed and the code did not have:
the request was read with `get_input_from(0)` and each maker's policy with
`get_input_from(i % N_PARTIES)`, so node 0 held the request --- `is_real`
included --- and one node held each policy in the clear. The circuit was
therefore a benchmark of party-supplied inputs, not of a venue that hides the
request from the people running it.

Checking it here rather than reading the generator is deliberate. The property
is about what ends up in `Player-Data/Input-P*-0`, which is the thing an
operator can actually look at, so that is what the tests read.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qomm_transport.roles import SLACK_BITS, check_field_width, split  # noqa: E402

N_PARTIES = 7
USER = {"asset": 1, "qty": 100, "dir": 0, "entity": 7}
N_ASSETS = 4


@pytest.fixture(scope="module")
def generated(tmp_path_factory):
    out = tmp_path_factory.mktemp("mpc")
    subprocess.run(
        [sys.executable, str(ROOT / "mp_spdz" / "gen_qomm.py"),
         "--n-mm", "4", "--n-parties", str(N_PARTIES),
         "--n-assets", str(N_ASSETS),
         "--user-asset", str(USER["asset"]), "--user-qty", str(USER["qty"]),
         "--user-dir", str(USER["dir"]), "--user-entity", str(USER["entity"]),
         "--out-program", str(out / "q.mpc"),
         "--out-input-dir", str(out / "in"),
         "--out-reference", str(out / "ref.json")],
        check=True, capture_output=True)
    files = {p: [int(v) for v in (out / "in" / f"Input-P{p}-0").read_text().split()]
             for p in range(N_PARTIES)}
    return files, (out / "q.mpc").read_text(), json.loads((out / "ref.json").read_text())


def test_every_node_holds_the_same_number_of_shares(generated):
    files, _, _ = generated
    counts = {p: len(v) for p, v in files.items()}
    assert len(set(counts.values())) == 1, (
        f"the nodes hold different numbers of inputs: {counts}. One holding more "
        "is one that was given something the others were not.")


def test_no_node_holds_a_request_value(generated):
    files, _, _ = generated
    for party, values in files.items():
        for name, secret in USER.items():
            assert secret not in values, (
                f"node {party} holds the request's {name} ({secret}) in the clear")
        assert 1 not in values and 0 not in values, (
            f"node {party} holds a bare flag; `is_real` is one bit and a share "
            "of it must not be that bit")


def test_no_node_holds_a_policy_value(generated):
    """Policy fields are small. A share is not, and that is the whole point."""
    files, _, _ = generated
    floor = 1 << (SLACK_BITS // 2)
    for party, values in files.items():
        small = [v for v in values if 0 <= v < floor]
        assert not small, (
            f"node {party} holds {len(small)} value(s) small enough to be a "
            f"policy field rather than a share of one: {small[:5]}")


def test_the_program_reads_a_share_from_every_node(generated):
    _, source, _ = generated
    assert "def secret_input():" in source
    assert "sint.get_input_from(_p)" in source, (
        "the program does not read from every node")
    assert "get_input_from(0)" in source.split("def secret_input():")[1][:200], (
        "the reconstruction should start at node 0")
    body = source.split("def secret_input():")[1]
    body = body[body.index("return total"):]
    assert "get_input_from" not in body, (
        "something outside `secret_input` still reads a party's input directly, "
        "which is the shape this test exists to prevent")


def test_the_shares_reconstruct_the_value():
    for value in (0, 1, 100, -50, 1_599_845):
        shares = split(value, N_PARTIES, 32)
        assert sum(shares) == value
        assert len(shares) == N_PARTIES


def test_one_share_moves_with_the_randomness_and_not_with_the_value():
    """Two values, one share each, drawn many times: the distributions overlap."""
    first = [split(0, N_PARTIES, 32)[0] for _ in range(200)]
    second = [split(10 ** 6, N_PARTIES, 32)[0] for _ in range(200)]
    assert len(set(first)) == 200, "a share repeated; the randomness is not fresh"
    assert min(first) < max(second) and min(second) < max(first), (
        "the two ranges do not overlap, so one share separates the values")


def test_a_field_too_narrow_for_the_shares_is_refused():
    check_field_width(N_PARTIES, 32, 128)
    with pytest.raises(ValueError, match="cannot hold"):
        check_field_width(N_PARTIES, 32, 64)
