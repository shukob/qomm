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
        """Decided by opening a difference, so no range proof is involved."""
        key = self.key
        difference = self._difference(left, right)
        proof = prove_opening(key, difference.commitment, difference.value,
                              difference.blinding, tag)
        self._proofs.append((label, "equality", proof, tag))
        self._commitments.append((label, "equality", difference.commitment))
        result = int(difference.value == 0) if op is ast.Eq else int(difference.value != 0)
        return self._as_bit(result, label, tag)

    def _walk_ordering(self, node, left: Wire, right: Wire, op, label: str,
                       tag: bytes) -> Wire:
        """`a >= b` is `a - b` not negative, which is one range proof."""
        key = self.key
        difference = (self._difference(left, right) if op in (ast.GtE, ast.Gt)
                      else self._difference(right, left))
        strict = op in (ast.Gt, ast.Lt)
        shifted = difference.value - 1 if strict else difference.value
        if shifted < 0:
            raise RuleError(
                f"the comparison {ast.unparse(node)} does not hold for these "
                f"values, so it cannot be proved")
        span = difference.interval
        bits = max(1, max(abs(span.lo), abs(span.hi)).bit_length() + 1)
        target = (shift_commitment(key, difference.commitment, 1) if strict
                  else difference.commitment)
        proof = prove_range(key, target, shifted, difference.blinding, bits, tag)
        self._proofs.append((label, "range", proof, tag))
        self._commitments.append((label, "range", (target, bits)))
        return self._as_bit(1, label, tag)

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


class RuleVerifier:
    def __init__(self, group: Group, key: Pedersen | None = None):
        self.group = group
        self.key = key or Pedersen(group, b"qomm:rule:v1")

    def verify(self, rule: Rule, audit: RuleAudit, context: bytes = b"") -> tuple[bool, str]:
        key = self.key
        for name, declaration in rule.declarations.items():
            if declaration.role == "input":
                continue
            proof = audit.declared_ranges.get(name)
            if proof is None:
                return False, f"'{name}' has no proof that it is inside its declared range"
            if not verify_bounded(key, audit.declared[name], proof,
                                  declaration.interval.lo, declaration.interval.hi,
                                  context + b":decl:" + name.encode()):
                return False, (f"'{name}' not shown to lie in "
                               f"[{declaration.interval.lo}, {declaration.interval.hi}]")

        for (label, kind, proof, tag), (_, _, commitments) in zip(audit.node_proofs,
                                                                   audit.node_commitments):
            if kind == "product":
                left, right, product = commitments
                if not verify_product(key, left, right, product, proof, tag):
                    return False, f"{label}: a product in the rule does not check out"
            elif kind == "range":
                target, bits = commitments
                if not verify_range(key, target, proof, tag):
                    return False, f"{label}: a comparison in the rule does not check out"
            elif kind == "bit":
                if not verify_bit(key, commitments, proof, tag):
                    return False, f"{label}: a condition is not a bit"
            elif kind == "equality":
                if not verify_opening(key, commitments, proof, tag):
                    return False, f"{label}: an equality in the rule does not check out"
        return True, "ok"
