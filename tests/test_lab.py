"""The interactive bench must assemble the same thing the scripts assemble.

Its whole value is that a question answered at the keyboard is answered against
the real simulation. If it drifted from run_sim_matrix, a result from it would
look like a finding and be a bug.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from qomm_sim import lab                                            # noqa: E402
from qomm_sim.engine import run_arm                                 # noqa: E402
from qomm_sim.experiment import DPParams, build_probes, make_disclosure  # noqa: E402
from qomm_sim.market import (                                       # noqa: E402
    ReferenceMarket, SimConfig, build_market_makers, build_requests,
)

SMALL = dict(steps=4_800, window_steps=120)


@pytest.fixture(scope="module")
def setup():
    return lab.build(**SMALL)


def test_it_builds_the_same_market_the_scripts_build(setup):
    cfg = SimConfig(steps=SMALL["steps"], window_steps=SMALL["window_steps"],
                    seed=20260818)
    market = ReferenceMarket(cfg, cfg.seed)
    requests = build_requests(cfg, market, cfg.seed + 2)
    assert len(setup.requests) == len(requests)
    assert [r.step for r in setup.requests] == [r.step for r in requests]
    assert market.mid == setup.market.mid


def test_one_arm_matches_running_it_directly(setup):
    cfg = SimConfig(steps=SMALL["steps"], window_steps=SMALL["window_steps"],
                    seed=20260818)
    market = ReferenceMarket(cfg, cfg.seed)
    direct = run_arm(cfg, market, build_requests(cfg, market, cfg.seed + 2),
                     build_market_makers(cfg, cfg.seed + 1), "plain_rfq",
                     make_disclosure("A_none", cfg, DPParams()), seed=cfg.seed + 5,
                     probes=build_probes(cfg, cfg.seed + 3, 6), reactive=False)
    assert lab.arm(setup, protocol="plain_rfq")["fill_rate"] == \
        direct.summary()["fill_rate"]


def test_arms_share_one_market(setup):
    """Otherwise a comparison between protocols includes a difference of markets."""
    rows = lab.compare(setup, protocols=("qomm_rfq", "plain_rfq"))
    assert rows[0]["fill_rate"] == rows[1]["fill_rate"]


def test_makers_do_not_carry_inventory_between_arms(setup):
    """A maker left holding a position would price the next arm differently."""
    first = lab.arm(setup, protocol="plain_rfq")
    second = lab.arm(setup, protocol="plain_rfq")
    assert first["fill_rate"] == second["fill_rate"]
    assert first["mm_pnl_per_fill"] == second["mm_pnl_per_fill"]


def test_the_query_oblivious_arm_is_flat_in_the_adversary(setup):
    rows = lab.sweep(setup, "rho", [0.0, 0.25, 0.5, 1.0], protocol="qomm_rfq")
    assert {row["detection_auc"] for row in rows} == {0.5}


def test_the_plain_arm_rises_with_the_adversary(setup):
    rows = lab.sweep(setup, "rho", [0.0, 0.25, 0.5, 1.0], protocol="plain_rfq")
    aucs = [row["detection_auc"] for row in rows]
    assert aucs == sorted(aucs)
    assert aucs[-1] > aucs[0]


def test_no_disclosure_reports_no_suppression(setup):
    """"Withheld" and "never offered" are different, and 1.0 reads as the first."""
    assert lab.arm(setup, disclosure="A_none")["suppression_rate"] is None
    assert lab.arm(setup, disclosure="C_dp")["suppression_rate"] is not None


def test_sweeping_epsilon_keeps_the_other_knobs_still(setup):
    rows = lab.sweep(setup, "epsilon", [0.25, 1.0, 4.0],
                     protocol="plain_rfq", disclosure="C_dp")
    assert [row["epsilon"] for row in rows] == [0.25, 1.0, 4.0]
    assert {row["protocol"] for row in rows} == {"plain_rfq"}


def test_the_table_renders_missing_values(setup):
    text = lab.table(lab.compare(setup))
    assert "n/a" in text and "qomm_rfq" in text
