"""Properties of the attacker's prior knowledge, pinned so it cannot drift back.

`linkage_rho` is the fraction of wallets whose controlling entity the adversary
already knows before the attack starts, and it sets almost the whole size of the
headline result: a linked entity is detected and an unlinked one is a coin flip,
so the baseline AUC lands near `0.5 + covered/2`. It was implemented by taking
every `round(1/rho)`-th wallet, which was wrong in three ways that all made the
adversary stronger than the number claimed.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from qomm_sim.attackers import _linked_wallets                      # noqa: E402
from qomm_sim.market import SimConfig                               # noqa: E402

CFG = SimConfig(n_entities=24, wallets_per_entity=3)
N_WALLETS = CFG.n_entities * CFG.wallets_per_entity


def test_no_linkage_means_no_wallets():
    """The stride version returned wallet 0 even at rho=0.

    `range(0, n, n + 1)` yields its start, so an adversary declared to know
    nothing still held one wallet, and the arm that was supposed to be the
    floor of the comparison was not one.
    """
    assert _linked_wallets(CFG, 0.0) == set()


def test_full_linkage_means_every_wallet():
    assert _linked_wallets(CFG, 1.0) == set(range(N_WALLETS))


def test_realised_fraction_matches_the_request():
    """A stride quantises: 0.75 and 1.0 both became stride 1, one experiment."""
    for rho in (0.05, 0.1, 0.12, 0.25, 0.33, 0.5, 0.66, 0.75, 0.9):
        linked = _linked_wallets(CFG, rho, seed=7)
        assert len(linked) == round(rho * N_WALLETS), rho
        assert abs(len(linked) / N_WALLETS - rho) <= 1.0 / N_WALLETS, rho


def test_distinct_fractions_stay_distinct():
    counts = {len(_linked_wallets(CFG, rho, seed=7)) for rho in (0.7, 0.75, 0.8, 0.9, 1.0)}
    assert len(counts) == 5


def test_half_the_wallets_is_not_all_the_firms():
    """The attack keys on the entity, so entity coverage is what rho buys.

    Wallet numbering is entity-major, so any stride below `wallets_per_entity`
    touches every entity: half the wallets de-anonymised all 24 firms.
    """
    linked = _linked_wallets(CFG, 0.5, seed=7)
    covered = {w // CFG.wallets_per_entity for w in linked}
    assert len(covered) < CFG.n_entities


def test_no_slot_bias_inside_an_entity():
    """A stride sharing a factor with the wallet count picks one slot in each firm."""
    cfg = SimConfig(n_entities=24, wallets_per_entity=3)
    for rho in (0.2, 0.33, 0.5):
        linked = _linked_wallets(cfg, rho, seed=11)
        slots = {w % cfg.wallets_per_entity for w in linked}
        assert slots == {0, 1, 2}, (rho, slots)


def test_sampling_reproduces_and_varies_with_the_seed():
    assert _linked_wallets(CFG, 0.3, seed=1) == _linked_wallets(CFG, 0.3, seed=1)
    assert _linked_wallets(CFG, 0.3, seed=1) != _linked_wallets(CFG, 0.3, seed=2)


def test_coverage_rises_monotonically_with_rho():
    previous = -1
    for rho in (0.0, 0.1, 0.25, 0.5, 0.75, 1.0):
        covered = len({w // CFG.wallets_per_entity for w in _linked_wallets(CFG, rho, seed=3)})
        assert covered >= previous, rho
        previous = covered
