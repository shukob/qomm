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
                active=1, use_ref=1, inv=-320, qty=100, ref_mid=100_000,
                now=1_000)


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
        "ask      = use_ref * ref_mid + mid + half + slope * qty + invcoef * inv",
        "ask      = use_ref * ref_mid + mid + half + slope * qty + invcoef * inv + slope * inv"))
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


# --- what a tampered audit must not get past the verifier ------------------
#
# The verifier used to `zip` the proofs it was handed against the commitments it
# was handed and check each pair. That asks "is every proof I was given valid"
# and never "were these the proofs the rule required", so an audit with the
# steps taken out passed. These are the shapes that used to pass.

import copy                                                            # noqa: E402

from qomm_dsl.audit import RuleAudit                                   # noqa: E402


@pytest.fixture(scope="module")
def honest(group):
    rule = compile_rule(QUOTE)
    audit = RuleProver(group).prove(rule, BINDINGS, b"ctx")
    return rule, audit


def _tampered(audit: RuleAudit, **changes) -> RuleAudit:
    fields = dict(declared=audit.declared, declared_ranges=audit.declared_ranges,
                  node_proofs=list(audit.node_proofs),
                  node_commitments=list(audit.node_commitments),
                  outputs=dict(audit.outputs), output_values=dict(audit.output_values))
    fields.update(changes)
    return RuleAudit(**fields)


def test_the_honest_audit_verifies(group, honest):
    rule, audit = honest
    assert RuleVerifier(group).verify(rule, audit, b"ctx") == (True, "ok")


def test_an_audit_with_no_steps_at_all_is_refused(group, honest):
    """The one that used to pass. `zip` over two empty lists checks nothing."""
    rule, audit = honest
    stripped = _tampered(audit, node_proofs=[], node_commitments=[])
    ok, why = RuleVerifier(group).verify(rule, stripped, b"ctx")
    assert not ok and "only 0 steps" in why


@pytest.mark.parametrize("drop", [0, 3, -1])
def test_an_audit_missing_one_step_is_refused(group, honest, drop):
    rule, audit = honest
    proofs = list(audit.node_proofs)
    commitments = list(audit.node_commitments)
    proofs.pop(drop)
    commitments.pop(drop)
    ok, why = RuleVerifier(group).verify(
        rule, _tampered(audit, node_proofs=proofs, node_commitments=commitments), b"ctx")
    assert not ok, f"a step was removed at {drop} and the audit still passed"


def test_an_audit_with_two_steps_swapped_is_refused(group, honest):
    rule, audit = honest
    proofs = list(audit.node_proofs)
    commitments = list(audit.node_commitments)
    proofs[0], proofs[1] = proofs[1], proofs[0]
    commitments[0], commitments[1] = commitments[1], commitments[0]
    ok, why = RuleVerifier(group).verify(
        rule, _tampered(audit, node_proofs=proofs, node_commitments=commitments), b"ctx")
    assert not ok


def test_an_audit_with_a_duplicated_step_is_refused(group, honest):
    rule, audit = honest
    proofs = list(audit.node_proofs)
    commitments = list(audit.node_commitments)
    proofs.insert(1, proofs[0])
    commitments.insert(1, commitments[0])
    ok, why = RuleVerifier(group).verify(
        rule, _tampered(audit, node_proofs=proofs, node_commitments=commitments), b"ctx")
    assert not ok


def test_an_audit_with_a_step_the_rule_does_not_ask_for_is_refused(group, honest):
    rule, audit = honest
    proofs = list(audit.node_proofs) + [audit.node_proofs[0]]
    commitments = list(audit.node_commitments) + [audit.node_commitments[0]]
    ok, why = RuleVerifier(group).verify(
        rule, _tampered(audit, node_proofs=proofs, node_commitments=commitments), b"ctx")
    assert not ok and "does not ask for" in why


def test_an_output_the_rule_does_not_compute_is_refused(group, honest):
    """Every proof still valid; the published answer is simply another one."""
    rule, audit = honest
    labels = list(audit.outputs)
    outputs = dict(audit.outputs)
    outputs[labels[0]] = audit.declared["mid"]
    ok, why = RuleVerifier(group).verify(rule, _tampered(audit, outputs=outputs), b"ctx")
    assert not ok and "does not compute" in why


def test_a_declared_commitment_swapped_for_another_is_refused(group, honest):
    rule, audit = honest
    declared = dict(audit.declared)
    declared["mid"], declared["half"] = declared["half"], declared["mid"]
    ok, why = RuleVerifier(group).verify(rule, _tampered(audit, declared=declared), b"ctx")
    assert not ok


def test_an_audit_for_a_different_rule_is_refused(group, honest):
    """The proofs are honest. They are honest about the wrong program."""
    _, audit = honest
    other = compile_rule(UPDATE)
    ok, why = RuleVerifier(group).verify(other, audit, b"ctx")
    assert not ok


# --- the bit a comparison returns is no longer the prover's to choose --------
#
# The old gadgets proved knowledge of an opening of the difference (free: the
# prover made the commitment) and committed the answer as an unrelated bit; and
# ordering raised when the comparison was false, so a condition could only ever
# evaluate to true. Both are now pinned by products the verifier's own
# arithmetic names the target of.

from zk.commit import prove_bit                                        # noqa: E402


def test_a_false_condition_can_now_be_proved_at_all(group):
    """The old prover raised. A maker that is ineligible could not be audited."""
    rule = compile_rule(QUOTE)
    for case in (dict(BINDINGS, expiry=500, now=1_000),
                 dict(BINDINGS, active=0),
                 dict(BINDINGS, qty=300, maxqty=100)):
        audit = RuleProver(group).prove(rule, case, b"ctx")
        assert RuleVerifier(group).verify(rule, audit, b"ctx") == (True, "ok")
        assert audit.output_values["eligible"] == 0


def _flip_first_bit(group, audit: RuleAudit) -> RuleAudit:
    """Answer the first comparison the other way, with a valid proof of the lie."""
    from qomm_dsl.audit import RuleVerifier as _V
    key = _V(group).key
    proofs = list(audit.node_proofs)
    commitments = list(audit.node_commitments)
    for i, (label, kind, _, tag) in enumerate(proofs):
        if kind != "bit":
            continue
        blinding = key.random_blinding()
        for lie in (0, 1):
            commitment = key.commit(lie, blinding)
            proofs[i] = (label, kind, prove_bit(key, commitment, lie, blinding, tag), tag)
            commitments[i] = (label, kind, commitment)
            if group.encode(commitment) != group.encode(audit.node_commitments[i][2]):
                return RuleAudit(audit.declared, audit.declared_ranges, proofs,
                                 commitments, audit.outputs, audit.output_values)
    raise AssertionError("the audit has no bit step to flip")


def test_a_flipped_condition_bit_is_refused(group, honest):
    """The bit proof is still valid. It is valid about the wrong answer."""
    rule, audit = honest
    forged = _flip_first_bit(group, audit)
    ok, why = RuleVerifier(group).verify(rule, forged, b"ctx")
    assert not ok, "a comparison answered the wrong way was accepted"


def test_the_equality_witness_cannot_claim_a_nonzero_difference_is_zero(group):
    """`b * d = 0` is what stops it, and it lands on a commitment we compute."""
    rule = compile_rule(QUOTE)
    audit = RuleProver(group).prove(rule, dict(BINDINGS, active=0), b"ctx")
    assert audit.output_values["eligible"] == 0
    forged = _flip_first_bit(group, audit)
    assert not RuleVerifier(group).verify(rule, forged, b"ctx")[0]


def test_the_strongest_consistent_forgery_still_fails_at_the_product(group):
    """Flip the bit *and* point every step that used it at the new one.

    This is the forgery a prover would actually attempt: the bit proof is
    honest about the lie, and the step that consumes the bit is re-proved to
    match. It still fails, because the bit is not pinned in one place. Every
    later step that touches it names a commitment this verifier derives for
    itself -- the identity for `bit * difference`, `g / C_b` for the inverse,
    `2P - S + B - g` for the comparison -- so moving the bit moves a target the
    prover does not control. Which check fires first is not the property; that
    one of them always does, is.
    """
    from zk.commit import prove_product                                # noqa: E402

    rule = compile_rule(QUOTE)
    audit = RuleProver(group).prove(rule, dict(BINDINGS, active=0), b"ctx")
    key = RuleVerifier(group).key

    index = next(i for i, (_, kind, _, _) in enumerate(audit.node_proofs)
                 if kind == "bit")
    old_bit = audit.node_commitments[index][2]
    label, _, _, tag = audit.node_proofs[index]
    blinding = key.random_blinding()
    lie = 1                                    # claim the condition held
    new_bit = key.commit(lie, blinding)

    proofs = list(audit.node_proofs)
    commitments = list(audit.node_commitments)
    proofs[index] = (label, "bit", prove_bit(key, new_bit, lie, blinding, tag), tag)
    commitments[index] = (label, "bit", new_bit)

    # every later step that named the old bit now names the new one, re-proved
    for i in range(index + 1, len(proofs)):
        step_label, kind, _, step_tag = proofs[i]
        if kind != "product":
            continue
        first, second, third = commitments[i]
        if group.encode(first) != group.encode(old_bit):
            continue
        commitments[i] = (step_label, kind, (new_bit, second, third))
        proofs[i] = (step_label, kind,
                     prove_product(key, new_bit, lie, blinding, 0, 0, 0, step_tag),
                     step_tag)
        break

    forged = RuleAudit(audit.declared, audit.declared_ranges, proofs, commitments,
                       audit.outputs, audit.output_values)
    ok, why = RuleVerifier(group).verify(rule, forged, b"ctx")
    assert not ok, "the forged audit was accepted"


def test_the_cost_model_counts_what_the_audit_actually_proves(group):
    """Two derivations of the same obligations, pinned to each other.

    `language.py` derives the obligations from the AST so a rule can be costed
    before anyone proves it; `audit.py` emits them while proving. Nothing kept
    the two in step, and they were not: inputs were graded as public, so a
    product touching one was costed at nothing while the prover proved it.
    A cost model that disagrees with the audit it is costing is worse than
    having none, because it is quoted.
    """
    import collections

    for source in (QUOTE, UPDATE):
        rule = compile_rule(source)
        bindings = dict(BINDINGS)
        for name, declaration in rule.declarations.items():
            bindings.setdefault(name, max(0, declaration.interval.lo))
        audit = RuleProver(group).prove(rule, bindings, b"ctx")
        planned = collections.Counter(o.kind for o in rule.obligations)
        proved = audit.size()
        for kind in ("product", "bit", "equality"):
            assert planned[kind] == proved.get(kind, 0), (
                f"{kind}: the plan says {planned[kind]} and the audit proves "
                f"{proved.get(kind, 0)}")
        assert planned["range"] == proved.get("range", 0) + proved["declared_range"]
        assert RuleVerifier(group).verify(rule, audit, b"ctx") == (True, "ok")
