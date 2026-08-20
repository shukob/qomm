"""The price-rule language: what it accepts, what it refuses, and what it derives.

The point of restricting the language is that the awkward properties Issue #129
asks for -- only permitted inputs, no dependence on who is asking, a finite
output range -- become static facts about a program rather than promises. These
tests are the checker's specification.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from qomm_dsl.audit import RuleProver, RuleVerifier                      # noqa: E402
from qomm_dsl.emit import evaluate, obligation_plan, to_mpc              # noqa: E402
from qomm_dsl.language import Interval, RuleError, compile_rule          # noqa: E402
from zk.groups import make_group                                         # noqa: E402

QUOTE = (ROOT / "qomm_dsl" / "examples" / "quote.rule").read_text()

UPDATE = (ROOT / "qomm_dsl" / "examples" / "update.rule").read_text()

BINDINGS = dict(mid=-6, half=14, slope=2, invcoef=1, maxqty=400, expiry=1_600,
                active=1, inv=-320, qty=100, ref_mid=100_000, now=1_000)


@pytest.fixture(scope="module")
def group():
    return make_group("ed25519")


# --- what the language refuses --------------------------------------------

@pytest.mark.parametrize("label,source,fragment", [
    ("identity as a pricing input",
     "param mid[1,2]\ninput wallet[0,9]\nask = mid + wallet", "who is asking"),
    ("division", "param mid[1,2]\ninput qty[1,9]\nask = mid / qty", "Div"),
    ("undeclared name", "param mid[1,2]\nask = mid + backdoor", "not declared"),
    ("degree three", "param a[1,2], b[1,2], c[1,2]\nask = a * b * c", "degree two"),
    ("attribute access", "param mid[1,2]\nask = mid.real", "not allowed"),
    ("arbitrary call", "param mid[1,2]\nask = pow(mid, 2)", "may be called"),
    ("comprehension", "param mid[1,2]\nask = sum([mid for _ in range(3)])", "may be called"),
    ("disjunction", "param a[0,1], b[0,1]\nok = (a == 1) or (b == 1)", "only 'and'"),
    ("floating point", "param mid[1,2]\nask = mid * 1.5", "integer constants"),
    ("chained comparison", "param a[1,9]\nok = 1 <= a <= 5", "chained"),
])
def test_forbidden_constructs_are_rejected(label, source, fragment):
    with pytest.raises(RuleError) as excinfo:
        compile_rule(source)
    assert fragment in str(excinfo.value), f"{label}: unexpected message"


@pytest.mark.parametrize("name", ["wallet", "entity", "user_id", "nullifier", "ip"])
def test_every_identity_input_is_refused(name):
    with pytest.raises(RuleError):
        compile_rule(f"param mid[1,2]\ninput {name}[0,9]\nask = mid + {name}")


def test_a_declared_but_unused_value_is_refused():
    with pytest.raises(RuleError) as excinfo:
        compile_rule("param mid[1,2], spare[0,9]\nask = mid + 1")
    assert "never used" in str(excinfo.value)


def test_a_rule_must_declare_and_produce_something():
    with pytest.raises(RuleError):
        compile_rule("ask = 1")
    with pytest.raises(RuleError):
        compile_rule("param mid[1,2]")


# --- what the checker derives ---------------------------------------------

def test_output_range_is_finite_and_computed_statically():
    rule = compile_rule(QUOTE)
    low, high = rule.intervals["ask"].as_tuple()
    assert low > 0 and high < 2 ** 20
    # the bound must contain an actual evaluation
    assert low <= evaluate(rule, BINDINGS)["ask"] <= high


def test_required_bit_width_follows_from_the_declared_bounds():
    rule = compile_rule(QUOTE)
    assert rule.required_bits() == rule.output_interval().width_bits()
    wider = compile_rule(QUOTE.replace("slope[0,16]", "slope[0,4096]"))
    assert wider.required_bits() > rule.required_bits()


def test_obligations_are_derived_not_written():
    rule = compile_rule(QUOTE)
    plan = obligation_plan(rule)
    # two secret-by-secret products in the quote, plus the conjunctions
    assert plan["counts"]["product"] >= 2
    assert plan["counts"]["range"] >= 2
    assert plan["total"] == len(rule.obligations)
    # adding a term to the rule adds its obligation automatically
    richer = compile_rule(QUOTE.replace(
        "ask      = ref_mid + mid + half + slope * qty + invcoef * inv",
        "ask      = ref_mid + mid + half + slope * qty + invcoef * inv + slope * inv"))
    assert obligation_plan(richer)["counts"]["product"] > plan["counts"]["product"]


def test_emitted_circuit_mentions_only_declared_columns():
    rule = compile_rule(QUOTE)
    emitted = to_mpc(rule)
    for expression in emitted.values():
        for token in expression.replace("(", " ").replace(")", " ").split():
            if token.startswith("col_"):
                assert token[4:] in rule.declarations


def test_declared_bounds_are_enforced_at_proving_time(group):
    rule = compile_rule(QUOTE)
    outside = dict(BINDINGS, half=900)
    with pytest.raises(RuleError):
        RuleProver(group).prove(rule, outside)


# --- the audit derived from the rule --------------------------------------

def test_the_derived_audit_verifies_and_matches_the_cleartext(group):
    rule = compile_rule(QUOTE)
    prover, verifier = RuleProver(group), RuleVerifier(group)
    audit = prover.prove(rule, BINDINGS)
    ok, reason = verifier.verify(rule, audit)
    assert ok, reason
    assert audit.output_values == evaluate(rule, BINDINGS)


def test_a_tampered_declared_range_proof_fails(group):
    rule = compile_rule(QUOTE)
    prover, verifier = RuleProver(group), RuleVerifier(group)
    audit = prover.prove(rule, BINDINGS)
    audit.declared_ranges["half"] = audit.declared_ranges["slope"]
    ok, reason = verifier.verify(rule, audit)
    assert not ok and "half" in reason


def test_a_missing_declared_range_proof_fails(group):
    rule = compile_rule(QUOTE)
    audit = RuleProver(group).prove(rule, BINDINGS)
    audit.declared_ranges.pop("slope")
    ok, reason = RuleVerifier(group).verify(rule, audit)
    assert not ok and "slope" in reason


def test_a_tampered_product_proof_fails(group):
    rule = compile_rule(QUOTE)
    audit = RuleProver(group).prove(rule, BINDINGS)
    products = [i for i, entry in enumerate(audit.node_proofs) if entry[1] == "product"]
    first, second = products[0], products[1]
    audit.node_proofs[first] = (audit.node_proofs[first][0], "product",
                                audit.node_proofs[second][2], audit.node_proofs[first][3])
    ok, reason = RuleVerifier(group).verify(rule, audit)
    assert not ok


# --- the state update rule uses exactly the same machinery ----------------

def test_the_state_update_rule_is_audited_the_same_way(group):
    rule = compile_rule(UPDATE, "update")
    prover, verifier = RuleProver(group), RuleVerifier(group)
    for inv, side, filled in ((-320, 0, 100), (3_900, 1, 250), (-3_900, 0, 400)):
        bindings = dict(inv=inv, side=side, fill_qty=filled)
        audit = prover.prove(rule, bindings)
        ok, reason = verifier.verify(rule, audit)
        assert ok, reason
        assert audit.output_values == evaluate(rule, bindings)


def test_the_update_rule_clamps_at_the_boundary(group):
    rule = compile_rule(UPDATE, "update")
    bindings = dict(inv=3_900, side=0, fill_qty=400)          # 4300 before clamping
    audit = RuleProver(group).prove(rule, bindings)
    assert audit.output_values["inv_next"] == 4_000
    assert RuleVerifier(group).verify(rule, audit)[0]


def test_the_update_output_range_is_the_declared_cap():
    rule = compile_rule(UPDATE, "update")
    assert rule.intervals["inv_next"].as_tuple() == (-4_000, 4_000)


# --- interval arithmetic --------------------------------------------------

def test_interval_arithmetic_covers_sign_changes():
    a, b = Interval(-3, 5), Interval(-2, 4)
    assert (a * b).as_tuple() == (-12, 20)
    assert (a - b).as_tuple() == (-7, 7)
    assert (-a).as_tuple() == (-5, 3)
    assert Interval(0, 1).width_bits() == 2
    assert Interval(-1000, 1000).width_bits() == 11
