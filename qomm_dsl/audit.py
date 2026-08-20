"""Turn a checked rule into real proofs by walking it once.

The same traversal that computes the value produces the proof for it. A market
maker registers a rule and its secret parameters; this module emits the
commitments and the sigma proofs that show every declared bound holds and every
product and comparison in the rule was evaluated correctly. Nothing about the
audit is written by hand, so a rule that gains a term gains the matching proof
automatically.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Mapping

from zk.commit import (
    BitProof, Pedersen, ProductProof, RangeProof, prove_bit, prove_bounded,
    prove_opening, prove_product, prove_range, shift_commitment, verify_bit,
    verify_bounded, verify_opening, verify_product, verify_range,
)
from zk.groups import Group

from .language import Interval, Rule, RuleError


@dataclass
class Wire:
    """A value as it travels up the tree: cleartext, blinding and commitment."""

    value: int
    blinding: int
    commitment: Any
    interval: Interval


@dataclass
class RuleAudit:
    declared: dict[str, Any]                 # name -> commitment
    declared_ranges: dict[str, RangeProof]
    node_proofs: list[tuple[str, str, Any, bytes]]   # (output, kind, proof, tag)
    node_commitments: list[tuple[str, str, Any]]
    outputs: dict[str, Any]                  # name -> commitment
    output_values: dict[str, int]

    def size(self) -> dict:
        counts: dict[str, int] = {}
        for _, kind, _, _ in self.node_proofs:
            counts[kind] = counts.get(kind, 0) + 1
        counts["declared_range"] = len(self.declared_ranges)
        return counts


class RuleProver:
    def __init__(self, group: Group, key: Pedersen | None = None):
        self.group = group
        self.key = key or Pedersen(group, b"qomm:rule:v1")

    def prove(self, rule: Rule, bindings: Mapping[str, int],
              context: bytes = b"") -> RuleAudit:
        key = self.key
        wires: dict[str, Wire] = {}
        declared: dict[str, Any] = {}
        declared_ranges: dict[str, RangeProof] = {}

        for name, declaration in rule.declarations.items():
            if name not in bindings:
                raise RuleError(f"no value supplied for '{name}'")
            value = bindings[name]
            low, high = declaration.interval.lo, declaration.interval.hi
            if not low <= value <= high:
                raise RuleError(
                    f"'{name}' = {value} is outside its declared range [{low}, {high}]")
            blinding = key.random_blinding()
            if declaration.role == "input":
                commitment = key.commit(value, blinding)
            else:
                # a secret parameter has to prove it sits inside the declared band
                commitment, proof, _ = prove_bounded(
                    key, value, blinding, low, high, context + b":decl:" + name.encode())
                declared_ranges[name] = proof
            declared[name] = commitment
            wires[name] = Wire(value, blinding, commitment, declaration.interval)

        self._proofs: list[tuple[str, str, Any, bytes]] = []
        self._commitments: list[tuple[str, str, Any]] = []
        outputs: dict[str, Any] = {}
        output_values: dict[str, int] = {}
        for label, tree in rule.outputs.items():
            wire = self._walk(tree.body, wires, label, context)
            outputs[label] = wire.commitment
            output_values[label] = wire.value

        return RuleAudit(declared, declared_ranges, self._proofs, self._commitments,
                         outputs, output_values)

    # --- one traversal, value and proof together ---
    # Dispatch by node type rather than by a chain of isinstance checks. The
    # chain was 107 lines with twenty branches, so the cost of a term and the
    # proof it needs were separated by everything else the language can express.
    # Each handler below is the whole answer for one construct.
    def _walk(self, node: ast.AST, wires: dict[str, Wire], label: str,
              context: bytes) -> Wire:
        handler = self._HANDLERS.get(type(node))
        if handler is None:
            raise RuleError(f"the prover has no rule for {type(node).__name__}")
        tag = context + b":" + label.encode() + b":" + str(len(self._proofs)).encode()
        return handler(self, node, wires, label, context, tag)

    def _walk_constant(self, node, wires, label, context, tag) -> Wire:
        value = int(node.value)
        return Wire(value, 0, self.key.commit(value, 0), Interval(value, value))

    def _walk_name(self, node, wires, label, context, tag) -> Wire:
        return wires[node.id]

    def _walk_unary(self, node, wires, label, context, tag) -> Wire:
        inner = self._walk(node.operand, wires, label, context)
        if not isinstance(node.op, ast.USub):
            return inner
        return Wire(-inner.value, (-inner.blinding) % self.group.order,
                    self.group.neg(inner.commitment), -inner.interval)

    def _walk_binop(self, node, wires, label, context, tag) -> Wire:
        left = self._walk(node.left, wires, label, context)
        right = self._walk(node.right, wires, label, context)
        if isinstance(node.op, (ast.Add, ast.Sub)):
            return self._walk_sum(left, right, adding=isinstance(node.op, ast.Add))
        if isinstance(node.op, ast.Mult):
            return self._walk_product(left, right, label, tag)
        raise RuleError("unsupported operator reached the prover")

    def _walk_sum(self, left: Wire, right: Wire, *, adding: bool) -> Wire:
        """Addition on commitments is free: no proof, and no round in the circuit."""
        sign = 1 if adding else -1
        commitment = (self.group.mul(left.commitment, right.commitment) if adding
                      else self.group.mul(left.commitment,
                                          self.group.neg(right.commitment)))
        return Wire(left.value + sign * right.value,
                    (left.blinding + sign * right.blinding) % self.group.order,
                    commitment,
                    left.interval + right.interval if adding
                    else left.interval - right.interval)

    def _walk_product(self, left: Wire, right: Wire, label: str, tag: bytes) -> Wire:
        """The one step that costs a proof."""
        key = self.key
        blinding = key.random_blinding()
        value = left.value * right.value
        proof = prove_product(key, left.commitment, left.value, left.blinding,
                              right.value, right.blinding, blinding, tag)
        commitment = key.commit(value, blinding)
        self._proofs.append((label, "product", proof, tag))
        self._commitments.append((label, "product",
                                  (left.commitment, right.commitment, commitment)))
        return Wire(value, blinding, commitment, left.interval * right.interval)

    def _walk_compare(self, node, wires, label, context, tag) -> Wire:
        left = self._walk(node.left, wires, label, context)
        right = self._walk(node.comparators[0], wires, label, context)
        op = type(node.ops[0])
        if op in (ast.Eq, ast.NotEq):
            return self._walk_equality(node, left, right, op, label, tag)
        return self._walk_ordering(node, left, right, op, label, tag)

    def _walk_equality(self, node, left: Wire, right: Wire, op, label: str,
                       tag: bytes) -> Wire:
        """`b = 1` exactly when the difference is zero, both directions proved.

        The old form proved knowledge of *an* opening of the difference and
        committed the answer as an independent bit. Knowing an opening of a
        commitment you made yourself is free, and an independent bit is a bit
        you choose, so nothing tied `b` to whether the two sides were equal --
        a prover could answer either way and be believed.

        What ties them is two products and the field's own arithmetic:

            b * d = 0        so b = 1 forces d = 0
            d * w = 1 - b    so b = 0 forces d invertible, hence d != 0

        `w` is the witness that d has an inverse; there is one exactly when d is
        not zero, which is what makes the second line unforgeable. Neither
        product's result has to be opened: both land on commitments the verifier
        derives for itself, the identity and `g / C_b`, so the only thing the
        prover chooses is `b` -- and it is now pinned from both sides.
        """
        key = self.key
        order = self.group.order
        difference = self._difference(left, right)
        is_zero = int(difference.value == 0)
        bit = self._as_bit(is_zero, label, tag)

        # b * d = 0, on a commitment with no blinding so the verifier can name it
        zero_product = prove_product(key, bit.commitment, is_zero, bit.blinding,
                                     difference.value, difference.blinding, 0,
                                     tag + b":bd")
        self._proofs.append((label, "product", zero_product, tag + b":bd"))
        self._commitments.append((label, "product",
                                  (bit.commitment, difference.commitment,
                                   key.commit(0, 0))))

        # d * w = 1 - b, on `g / C_b`, which the verifier derives
        witness = 0 if is_zero else pow(difference.value % order, -1, order)
        witness_blinding = key.random_blinding()
        inverse_product = prove_product(key, difference.commitment, difference.value,
                                        difference.blinding, witness, witness_blinding,
                                        (-bit.blinding) % order, tag + b":dw")
        self._proofs.append((label, "product", inverse_product, tag + b":dw"))
        self._commitments.append((label, "product",
                                  (difference.commitment,
                                   key.commit(witness, witness_blinding),
                                   self.group.mul(key.commit(1, 0),
                                                  self.group.neg(bit.commitment)))))
        if op is ast.Eq:
            return bit
        # `!=` is the same evidence read the other way: 1 - b, and no new proof
        return Wire(1 - bit.value, (-bit.blinding) % order,
                    self.group.mul(key.commit(1, 0), self.group.neg(bit.commitment)),
                    Interval(0, 1))

    def _walk_ordering(self, node, left: Wire, right: Wire, op, label: str,
                       tag: bytes) -> Wire:
        """`a >= b` as a bit that can be either, with one range proof either way.

        The old form range-proved `a - b >= 0` and returned the constant 1, and
        raised when the comparison was false. So the language could not express
        a false comparison at all: every condition in a rule evaluated to true
        by construction, which makes a conditional price rule unauditable and
        the gate bits meaningless.

        The bit is now free and one range proof covers both cases:

            t = b * s + (1 - b) * (-s - 1),   proved t >= 0

        b = 1 gives t = s, so s >= 0. b = 0 gives t = -s - 1, so s <= -1. One
        product for `b * s`, and `t` is then a commitment the verifier derives.
        """
        key = self.key
        order = self.group.order
        span_wire = (self._difference(left, right) if op in (ast.GtE, ast.Gt)
                     else self._difference(right, left))
        strict = op in (ast.Gt, ast.Lt)
        # `a > b` is `a - b - 1 >= 0`; fold the shift in so one gadget serves both
        shifted = Wire(span_wire.value - 1, span_wire.blinding,
                       shift_commitment(key, span_wire.commitment, 1),
                       span_wire.interval - Interval(1, 1)) if strict else span_wire

        holds = int(shifted.value >= 0)
        bit = self._as_bit(holds, label, tag)

        product_blinding = key.random_blinding()
        product = prove_product(key, bit.commitment, holds, bit.blinding,
                                shifted.value, shifted.blinding, product_blinding,
                                tag + b":bs")
        product_commitment = key.commit(holds * shifted.value, product_blinding)
        self._proofs.append((label, "product", product, tag + b":bs"))
        self._commitments.append((label, "product",
                                  (bit.commitment, shifted.commitment,
                                   product_commitment)))

        # t = 2*b*s - s + b - 1, and its commitment follows from the ones above
        witness = 2 * holds * shifted.value - shifted.value + holds - 1
        witness_blinding = (2 * product_blinding - shifted.blinding
                            + bit.blinding) % order
        span = shifted.interval
        bits = max(1, (max(abs(span.lo), abs(span.hi)) + 1).bit_length() + 1)
        target = self._t_commitment(product_commitment, shifted.commitment,
                                    bit.commitment)
        proof = prove_range(key, target, witness, witness_blinding, bits, tag)
        self._proofs.append((label, "range", proof, tag))
        self._commitments.append((label, "range", (target, bits)))
        return bit

    def _t_commitment(self, product, difference, bit):
        """`2P - S + B - g`, the commitment the range proof above is about."""
        group = self.group
        acc = group.mul(group.point_pow(product, 2), group.neg(difference))
        acc = group.mul(acc, bit)
        return group.mul(acc, group.neg(self.key.commit(1, 0)))

    def _as_bit(self, value: int, label: str, tag: bytes) -> Wire:
        """Commit a comparison's result and prove it really is a bit."""
        key = self.key
        blinding = key.random_blinding()
        commitment = key.commit(value, blinding)
        proof = prove_bit(key, commitment, value, blinding, tag + b":bit")
        self._proofs.append((label, "bit", proof, tag + b":bit"))
        self._commitments.append((label, "bit", commitment))
        return Wire(value, blinding, commitment, Interval(0, 1))

    def _walk_boolop(self, node, wires, label, context, tag) -> Wire:
        """A conjunction is a product of bits: one multiplication each."""
        wire = self._walk(node.values[0], wires, label, context)
        for value_node in node.values[1:]:
            other = self._walk(value_node, wires, label, context)
            and_tag = tag + b":and:" + str(len(self._proofs)).encode()
            wire = self._walk_product(wire, other, label, and_tag)
            wire = Wire(wire.value, wire.blinding, wire.commitment, Interval(0, 1))
        return wire

    def _walk_call_node(self, node, wires, label, context, tag) -> Wire:
        return self._walk_call(node, wires, label, context, tag)

    _HANDLERS = {
        ast.Constant: _walk_constant,
        ast.Name: _walk_name,
        ast.UnaryOp: _walk_unary,
        ast.BinOp: _walk_binop,
        ast.Compare: _walk_compare,
        ast.BoolOp: _walk_boolop,
        ast.Call: _walk_call_node,
    }

    def _prove_ge_zero(self, wire: Wire, tag: bytes) -> None:
        """Show a committed difference is not negative."""
        bits = max(1, max(abs(wire.interval.lo), abs(wire.interval.hi)).bit_length() + 1)
        proof = prove_range(self.key, wire.commitment, wire.value, wire.blinding, bits, tag)
        self._proofs.append(("_", "range", proof, tag))
        self._commitments.append(("_", "range", (wire.commitment, bits)))

    def _difference(self, left: Wire, right: Wire) -> Wire:
        order = self.group.order
        return Wire(left.value - right.value,
                    (left.blinding - right.blinding) % order,
                    self.group.mul(left.commitment, self.group.neg(right.commitment)),
                    left.interval - right.interval)

    def _walk_call(self, node: ast.Call, wires, label: str, context: bytes,
                   tag: bytes) -> Wire:
        """min, max, clamp and signed, each with the proof that makes it sound."""
        name = node.func.id
        args = [self._walk(argument, wires, label, context) for argument in node.args]
        builder = {
            "min": lambda: self._select(args[0], args[1], label, tag, take_min=True),
            "max": lambda: self._select(args[0], args[1], label, tag, take_min=False),
            "clamp": lambda: self._clamp(args, label, tag),
            "signed": lambda: self._signed(args[0], args[1], label, tag),
        }.get(name)
        if builder is None:
            raise RuleError(f"the prover has no rule for the intrinsic {name}")
        return builder()

    def _select(self, left: Wire, right: Wire, label: str, tag: bytes, *,
                take_min: bool) -> Wire:
        """min or max, proved without revealing which branch was taken.

        The argument is: the result is no worse than either input, and it equals
        one of them. The second half is a single product opening to zero, which
        is cheaper and simpler than proving the branch.
        """
        key = self.key
        value = min(left.value, right.value) if take_min else max(left.value, right.value)
        blinding = key.random_blinding()
        interval = (Interval(min(left.interval.lo, right.interval.lo),
                             min(left.interval.hi, right.interval.hi)) if take_min
                    else Interval(max(left.interval.lo, right.interval.lo),
                                  max(left.interval.hi, right.interval.hi)))
        result = Wire(value, blinding, key.commit(value, blinding), interval)

        first = (self._difference(left, result) if take_min
                 else self._difference(result, left))
        second = (self._difference(right, result) if take_min
                  else self._difference(result, right))
        self._prove_ge_zero(first, tag + b":a")
        self._prove_ge_zero(second, tag + b":b")
        self._pin_to_one_of(left, right, result, label, tag)
        return result

    def _pin_to_one_of(self, left: Wire, right: Wire, result: Wire, label: str,
                       tag: bytes) -> None:
        """`(left - result) * (right - result) == 0` says the result is one of them."""
        key = self.key
        gap_left = self._difference(left, result)
        gap_right = self._difference(right, result)
        zero_blinding = key.random_blinding()
        product = prove_product(key, gap_left.commitment, gap_left.value,
                                gap_left.blinding, gap_right.value,
                                gap_right.blinding, zero_blinding, tag + b":pin")
        zero_commitment = key.commit(gap_left.value * gap_right.value, zero_blinding)
        self._proofs.append((label, "product", product, tag + b":pin"))
        self._commitments.append((label, "product",
                                  (gap_left.commitment, gap_right.commitment,
                                   zero_commitment)))
        opening = prove_opening(key, zero_commitment, 0, zero_blinding, tag + b":zero")
        self._proofs.append((label, "equality", opening, tag + b":zero"))
        self._commitments.append((label, "equality", zero_commitment))

    def _clamp(self, args: list[Wire], label: str, tag: bytes) -> Wire:
        """A floor then a ceiling, which is max then min and nothing new."""
        value, lo, hi = args
        lowered = self._select(value, lo, label, tag + b":lo", take_min=False)
        return self._select(lowered, hi, label, tag + b":hi", take_min=True)

    def _signed(self, side: Wire, magnitude: Wire, label: str, tag: bytes) -> Wire:
        """`side ? -magnitude : magnitude`, as `magnitude - 2 * side * magnitude`.

        Written as arithmetic rather than as a branch, so nothing about which way
        the trade went has to be opened.
        """
        key = self.key
        blinding = key.random_blinding()
        product_value = side.value * magnitude.value
        proof = prove_product(key, side.commitment, side.value, side.blinding,
                              magnitude.value, magnitude.blinding, blinding,
                              tag + b":signed")
        product_commitment = key.commit(product_value, blinding)
        self._proofs.append((label, "product", proof, tag + b":signed"))
        self._commitments.append((label, "product",
                                  (side.commitment, magnitude.commitment,
                                   product_commitment)))
        return Wire(
            magnitude.value - 2 * product_value,
            (magnitude.blinding - 2 * blinding) % self.group.order,
            self.group.mul(magnitude.commitment,
                           self.group.neg(self.group.point_pow(product_commitment, 2))),
            Interval(-magnitude.interval.hi, magnitude.interval.hi))


@dataclass
class Shape:
    """A wire as the verifier sees it: a commitment and a public interval.

    No value and no blinding. Everything the verifier needs about a term is
    either homomorphically derivable from the declared commitments or pinned to
    them by a proof, and this is the type that carries the derivable half.
    """

    commitment: Any
    interval: Interval


class AuditMismatch(Exception):
    """The audit is not the one this rule asks for."""


class _Cursor:
    """The audit's steps, consumed in the order the rule generates them.

    This is the whole fix. The verifier used to `zip` the proofs it was handed
    with the commitments it was handed and check each pair, which asks "is every
    proof I was given valid" and never asks "were these the proofs the rule
    required". An audit missing every step passed. So the steps are now demanded
    one at a time by a walk over the registered rule, and the walk fails if the
    next step is not the one the rule says comes next --- missing, extra,
    reordered and duplicated are all the same failure to it.
    """

    def __init__(self, audit: RuleAudit):
        self.audit = audit
        self.at = 0

    def take(self, label: str, kind: str, tag: bytes):
        if self.at >= len(self.audit.node_proofs):
            raise AuditMismatch(
                f"the rule requires a {kind} step for '{label}' and the audit "
                f"has only {len(self.audit.node_proofs)} steps")
        got_label, got_kind, proof, got_tag = self.audit.node_proofs[self.at]
        c_label, c_kind, commitments = self.audit.node_commitments[self.at]
        if (got_label, got_kind, got_tag) != (label, kind, tag):
            raise AuditMismatch(
                f"step {self.at} should be {kind} for '{label}' and is "
                f"{got_kind} for '{got_label}'")
        if (c_label, c_kind) != (label, kind):
            raise AuditMismatch(
                f"step {self.at}: the proof and its commitments disagree about "
                f"what they are for")
        self.at += 1
        return proof, commitments, tag

    def finish(self) -> None:
        if self.at != len(self.audit.node_proofs):
            raise AuditMismatch(
                f"the audit carries {len(self.audit.node_proofs) - self.at} "
                "step(s) the rule does not ask for")
        if len(self.audit.node_proofs) != len(self.audit.node_commitments):
            raise AuditMismatch("proofs and commitments are different lengths")


class RuleVerifier:
    """Walks the registered rule and demands the audit that rule requires.

    The traversal below mirrors `RuleProver` node for node. Where the prover has
    a value and emits a proof, the verifier has a commitment and consumes one.
    Every commitment is either derived from the declared ones by the
    homomorphism --- sums, differences, negations, constants --- or is
    prover-chosen and pinned to derived ones by the proof at that step. A
    commitment that is neither is a commitment the rule never mentioned.
    """

    def __init__(self, group: Group, key: Pedersen | None = None):
        self.group = group
        self.key = key or Pedersen(group, b"qomm:rule:v1")

    def verify(self, rule: Rule, audit: RuleAudit, context: bytes = b"") -> tuple[bool, str]:
        key = self.key
        try:
            shapes = self._declarations(rule, audit, context)
            cursor = _Cursor(audit)
            for label, tree in rule.outputs.items():
                if label not in audit.outputs:
                    raise AuditMismatch(f"the audit has no output '{label}'")
                shape = self._walk(tree.body, shapes, label, context, cursor)
                if self.group.encode(shape.commitment) != self.group.encode(
                        audit.outputs[label]):
                    raise AuditMismatch(
                        f"'{label}' is published as a commitment the rule does "
                        "not compute")
            for label in audit.outputs:
                if label not in rule.outputs:
                    raise AuditMismatch(
                        f"the audit publishes '{label}', which the rule does not")
            cursor.finish()
        except AuditMismatch as mismatch:
            return False, str(mismatch)
        except (KeyError, TypeError, ValueError) as broken:
            return False, f"the audit is malformed: {broken}"
        return True, "ok"

    def _declarations(self, rule: Rule, audit: RuleAudit, context: bytes) -> dict[str, Shape]:
        key = self.key
        shapes: dict[str, Shape] = {}
        for name, declaration in rule.declarations.items():
            if name not in audit.declared:
                raise AuditMismatch(f"'{name}' has no commitment in the audit")
            commitment = audit.declared[name]
            if declaration.role != "input":
                proof = audit.declared_ranges.get(name)
                if proof is None:
                    raise AuditMismatch(
                        f"'{name}' has no proof that it is inside its declared range")
                if not verify_bounded(key, commitment, proof,
                                      declaration.interval.lo, declaration.interval.hi,
                                      context + b":decl:" + name.encode()):
                    raise AuditMismatch(
                        f"'{name}' not shown to lie in "
                        f"[{declaration.interval.lo}, {declaration.interval.hi}]")
            shapes[name] = Shape(commitment, declaration.interval)
        for name in audit.declared:
            if name not in rule.declarations:
                raise AuditMismatch(f"the audit declares '{name}', which the rule does not")
        for name in audit.declared_ranges:
            if name not in rule.declarations:
                raise AuditMismatch(f"the audit ranges '{name}', which the rule does not")
        return shapes

    # --- the mirror of RuleProver._walk ---

    def _walk(self, node: ast.AST, shapes: dict[str, Shape], label: str,
              context: bytes, cursor: _Cursor) -> Shape:
        handler = self._HANDLERS.get(type(node))
        if handler is None:
            raise AuditMismatch(f"the rule contains {type(node).__name__}, "
                                "which the verifier has no rule for")
        tag = context + b":" + label.encode() + b":" + str(cursor.at).encode()
        return handler(self, node, shapes, label, context, tag, cursor)

    def _v_constant(self, node, shapes, label, context, tag, cursor) -> Shape:
        value = int(node.value)
        return Shape(self.key.commit(value, 0), Interval(value, value))

    def _v_name(self, node, shapes, label, context, tag, cursor) -> Shape:
        if node.id not in shapes:
            raise AuditMismatch(f"the rule reads '{node.id}', which it never declared")
        return shapes[node.id]

    def _v_unary(self, node, shapes, label, context, tag, cursor) -> Shape:
        inner = self._walk(node.operand, shapes, label, context, cursor)
        if not isinstance(node.op, ast.USub):
            return inner
        return Shape(self.group.neg(inner.commitment), -inner.interval)

    def _v_binop(self, node, shapes, label, context, tag, cursor) -> Shape:
        left = self._walk(node.left, shapes, label, context, cursor)
        right = self._walk(node.right, shapes, label, context, cursor)
        if isinstance(node.op, (ast.Add, ast.Sub)):
            adding = isinstance(node.op, ast.Add)
            commitment = (self.group.mul(left.commitment, right.commitment) if adding
                          else self.group.mul(left.commitment,
                                              self.group.neg(right.commitment)))
            return Shape(commitment,
                         left.interval + right.interval if adding
                         else left.interval - right.interval)
        if isinstance(node.op, ast.Mult):
            return self._v_product(left, right, label, tag, cursor)
        raise AuditMismatch("the rule contains an operator the verifier cannot check")

    def _v_product(self, left: Shape, right: Shape, label: str, tag: bytes,
                   cursor: _Cursor) -> Shape:
        proof, commitments, tag = cursor.take(label, "product", tag)
        got_left, got_right, product = commitments
        self._same(got_left, left.commitment, "the left factor of a product")
        self._same(got_right, right.commitment, "the right factor of a product")
        if not verify_product(self.key, got_left, got_right, product, proof, tag):
            raise AuditMismatch(f"{label}: a product in the rule does not check out")
        return Shape(product, left.interval * right.interval)

    def _v_compare(self, node, shapes, label, context, tag, cursor) -> Shape:
        left = self._walk(node.left, shapes, label, context, cursor)
        right = self._walk(node.comparators[0], shapes, label, context, cursor)
        op = type(node.ops[0])
        if op in (ast.Eq, ast.NotEq):
            return self._v_equality(left, right, op, label, tag, cursor)
        return self._v_ordering(left, right, op, label, tag, cursor)

    def _v_equality(self, left: Shape, right: Shape, op, label: str, tag: bytes,
                    cursor: _Cursor) -> Shape:
        """Both directions, or the bit is the prover's to choose.

        `b * d = 0` lands on the identity and `d * w = 1 - b` lands on `g / C_b`.
        Both targets are commitments this verifier computes, so neither product
        gives the prover anywhere to hide: b = 1 forces d = 0 and b = 0 forces d
        to have an inverse.
        """
        group, key = self.group, self.key
        difference = self._difference(left, right)
        bit = self._v_bit(label, tag, cursor)

        proof, commitments, bd_tag = cursor.take(label, "product", tag + b":bd")
        got_bit, got_difference, zero = commitments
        self._same(got_bit, bit.commitment, "the bit of an equality")
        self._same(got_difference, difference.commitment,
                   "the difference an equality is decided on")
        self._same(zero, key.commit(0, 0),
                   "the product an equality has to send to zero")
        if not verify_product(key, got_bit, got_difference, zero, proof, bd_tag):
            raise AuditMismatch(f"{label}: `bit * difference = 0` does not check out")

        proof, commitments, dw_tag = cursor.take(label, "product", tag + b":dw")
        got_difference, witness, one_minus_bit = commitments
        self._same(got_difference, difference.commitment,
                   "the difference an equality inverts")
        expected = group.mul(key.commit(1, 0), group.neg(bit.commitment))
        self._same(one_minus_bit, expected,
                   "the product an equality has to send to `1 - bit`")
        if not verify_product(key, got_difference, witness, one_minus_bit, proof,
                              dw_tag):
            raise AuditMismatch(
                f"{label}: the difference is not shown to be invertible when the "
                "bit says the two sides differ")
        if op is ast.Eq:
            return bit
        return Shape(expected, Interval(0, 1))

    def _v_ordering(self, left: Shape, right: Shape, op, label: str, tag: bytes,
                    cursor: _Cursor) -> Shape:
        """One range proof that covers both answers, so the bit is not free."""
        group, key = self.group, self.key
        span_shape = (self._difference(left, right) if op in (ast.GtE, ast.Gt)
                      else self._difference(right, left))
        strict = op in (ast.Gt, ast.Lt)
        shifted = (Shape(shift_commitment(key, span_shape.commitment, 1),
                         span_shape.interval - Interval(1, 1))
                   if strict else span_shape)

        bit = self._v_bit(label, tag, cursor)
        proof, commitments, bs_tag = cursor.take(label, "product", tag + b":bs")
        got_bit, got_span, product = commitments
        self._same(got_bit, bit.commitment, "the bit of a comparison")
        self._same(got_span, shifted.commitment,
                   "the difference a comparison is decided on")
        if not verify_product(key, got_bit, got_span, product, proof, bs_tag):
            raise AuditMismatch(f"{label}: `bit * difference` does not check out")

        span = shifted.interval
        bits = max(1, (max(abs(span.lo), abs(span.hi)) + 1).bit_length() + 1)
        expected = self._t_commitment(product, shifted.commitment, bit.commitment)
        proof, commitments, range_tag = cursor.take(label, "range", tag)
        target, got_bits = commitments
        self._same(target, expected,
                   "the value a comparison shows to be non-negative")
        if got_bits != bits:
            raise AuditMismatch(
                f"{label}: the comparison is proved over {got_bits} bits and the "
                f"rule's declared intervals need {bits}")
        if not verify_range(key, target, proof, range_tag):
            raise AuditMismatch(f"{label}: a comparison in the rule does not check out")
        return bit

    def _t_commitment(self, product, difference, bit):
        group = self.group
        acc = group.mul(group.point_pow(product, 2), group.neg(difference))
        acc = group.mul(acc, bit)
        return group.mul(acc, group.neg(self.key.commit(1, 0)))

    def _v_bit(self, label: str, tag: bytes, cursor: _Cursor) -> Shape:
        proof, commitment, bit_tag = cursor.take(label, "bit", tag + b":bit")
        if not verify_bit(self.key, commitment, proof, bit_tag):
            raise AuditMismatch(f"{label}: a condition is not a bit")
        return Shape(commitment, Interval(0, 1))

    def _v_boolop(self, node, shapes, label, context, tag, cursor) -> Shape:
        shape = self._walk(node.values[0], shapes, label, context, cursor)
        for value_node in node.values[1:]:
            other = self._walk(value_node, shapes, label, context, cursor)
            and_tag = tag + b":and:" + str(cursor.at).encode()
            shape = self._v_product(shape, other, label, and_tag, cursor)
            shape = Shape(shape.commitment, Interval(0, 1))
        return shape

    def _v_call(self, node, shapes, label, context, tag, cursor) -> Shape:
        name = node.func.id
        args = [self._walk(argument, shapes, label, context, cursor)
                for argument in node.args]
        if name in ("min", "max"):
            return self._v_select(args[0], args[1], label, tag, cursor,
                                  take_min=name == "min")
        if name == "clamp":
            lowered = self._v_select(args[0], args[1], label, tag + b":lo", cursor,
                                     take_min=False)
            return self._v_select(lowered, args[2], label, tag + b":hi", cursor,
                                  take_min=True)
        if name == "signed":
            return self._v_signed(args[0], args[1], label, tag, cursor)
        raise AuditMismatch(f"the rule calls {name}, which the verifier cannot check")

    def _v_select(self, left: Shape, right: Shape, label: str, tag: bytes,
                  cursor: _Cursor, *, take_min: bool) -> Shape:
        """min or max. The result's commitment is recovered from the first step.

        The prover never publishes the selected value's commitment on its own;
        it appears only inside the differences it proves non-negative. So it is
        read back out of the first of those, and then every remaining step has
        to agree with it --- which is what stops the prover using a different
        result in each half of the argument.
        """
        group = self.group
        first_proof, first_commitments, first_tag = cursor.take("_", "range", tag + b":a")
        first_target, first_bits = first_commitments
        # take_min: first = left - result, so result = left - first
        # take_max: first = result - left, so result = first + left
        result_commitment = (group.mul(left.commitment, group.neg(first_target))
                             if take_min else group.mul(first_target, left.commitment))
        interval = (Interval(min(left.interval.lo, right.interval.lo),
                             min(left.interval.hi, right.interval.hi)) if take_min
                    else Interval(max(left.interval.lo, right.interval.lo),
                                  max(left.interval.hi, right.interval.hi)))
        result = Shape(result_commitment, interval)

        first = (self._difference(left, result) if take_min
                 else self._difference(result, left))
        second = (self._difference(right, result) if take_min
                  else self._difference(result, right))
        self._check_ge_zero(first, first_proof, first_target, first_bits, first_tag)
        self._take_ge_zero(second, tag + b":b", cursor)
        self._v_pin(left, right, result, label, tag, cursor)
        return result

    def _take_ge_zero(self, shape: Shape, tag: bytes, cursor: _Cursor) -> None:
        proof, commitments, got_tag = cursor.take("_", "range", tag)
        target, bits = commitments
        self._check_ge_zero(shape, proof, target, bits, got_tag)

    def _check_ge_zero(self, shape: Shape, proof, target, bits: int, tag: bytes) -> None:
        self._same(target, shape.commitment, "a difference proved non-negative")
        expected = max(1, max(abs(shape.interval.lo),
                              abs(shape.interval.hi)).bit_length() + 1)
        if bits != expected:
            raise AuditMismatch(
                f"a non-negativity proof is over {bits} bits where the rule's "
                f"intervals need {expected}")
        if not verify_range(self.key, target, proof, tag):
            raise AuditMismatch("a selection's non-negativity does not check out")

    def _v_pin(self, left: Shape, right: Shape, result: Shape, label: str,
               tag: bytes, cursor: _Cursor) -> None:
        gap_left = self._difference(left, result)
        gap_right = self._difference(right, result)
        proof, commitments, pin_tag = cursor.take(label, "product", tag + b":pin")
        got_left, got_right, zero_commitment = commitments
        self._same(got_left, gap_left.commitment, "the left gap of a selection")
        self._same(got_right, gap_right.commitment, "the right gap of a selection")
        if not verify_product(self.key, got_left, got_right, zero_commitment,
                              proof, pin_tag):
            raise AuditMismatch(f"{label}: a selection's product does not check out")
        opening, got_zero, zero_tag = cursor.take(label, "equality", tag + b":zero")
        self._same(got_zero, zero_commitment,
                   "the product a selection opens to zero")
        if not verify_opening(self.key, got_zero, opening, zero_tag):
            raise AuditMismatch(f"{label}: a selection is not pinned to one of its inputs")

    def _v_signed(self, side: Shape, magnitude: Shape, label: str, tag: bytes,
                  cursor: _Cursor) -> Shape:
        proof, commitments, signed_tag = cursor.take(label, "product", tag + b":signed")
        got_side, got_magnitude, product = commitments
        self._same(got_side, side.commitment, "the sign of a signed term")
        self._same(got_magnitude, magnitude.commitment, "the magnitude of a signed term")
        if not verify_product(self.key, got_side, got_magnitude, product, proof,
                              signed_tag):
            raise AuditMismatch(f"{label}: a signed term does not check out")
        commitment = self.group.mul(magnitude.commitment,
                                    self.group.neg(self.group.point_pow(product, 2)))
        return Shape(commitment, Interval(-magnitude.interval.hi, magnitude.interval.hi))

    def _difference(self, left: Shape, right: Shape) -> Shape:
        return Shape(self.group.mul(left.commitment, self.group.neg(right.commitment)),
                     left.interval - right.interval)

    def _same(self, got, expected, what: str) -> None:
        if self.group.encode(got) != self.group.encode(expected):
            raise AuditMismatch(f"{what} is not the one the rule computes")

    _HANDLERS = {
        ast.Constant: _v_constant,
        ast.Name: _v_name,
        ast.UnaryOp: _v_unary,
        ast.BinOp: _v_binop,
        ast.Compare: _v_compare,
        ast.BoolOp: _v_boolop,
        ast.Call: _v_call,
    }
