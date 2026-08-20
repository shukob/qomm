"""Parse, check and analyse a market-maker price rule.

Issue #129 asks for the price rule to be restricted to "an approved circuit, or a
small description format with a limited instruction set", and to check that it

    references only permitted inputs
    does not use the user's identity or wallet address as a pricing input
    sends no secret out during evaluation
    has a finite output range and expiry

Those are static properties of a program, not runtime facts, so they belong in a
checker rather than in a proof. What the checker produces is the interesting
part: from one source it derives the MPC circuit, the list of zero-knowledge
obligations, and the bit width the circuit needs. The audit stops being
hand-written and starts being a compiler output, which is the point of having a
language at all.

The surface syntax is a subset of Python expressions, parsed with the standard
`ast` module and then filtered against an allow-list of node types. Anything not
on the list -- calls other than the named intrinsics, attribute access, indexing,
comprehensions, lambdas, division -- is rejected before it can mean anything.
"""

from __future__ import annotations

import ast
import math
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

# Identifiers a price rule may never read. Reading any of these would let the
# quote depend on who is asking, which is the whole thing the design forbids.
FORBIDDEN_INPUTS = frozenset({
    "wallet", "address", "entity", "entity_id", "user", "user_id", "client",
    "counterparty", "name", "kyc_id", "nullifier", "ip",
})

INTRINSICS = frozenset({"min", "max", "clamp", "signed"})

ALLOWED_NODES = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.Name, ast.Constant, ast.Call,
    ast.Load, ast.Add, ast.Sub, ast.Mult, ast.USub, ast.UAdd,
    ast.Compare, ast.LtE, ast.Lt, ast.GtE, ast.Gt, ast.Eq, ast.NotEq,
    ast.BoolOp, ast.And,
)


class RuleError(ValueError):
    """Raised when a rule is rejected. The message names the exact reason."""


@dataclass(frozen=True)
class Interval:
    lo: int
    hi: int

    def __post_init__(self):
        if self.lo > self.hi:
            raise RuleError(f"empty interval [{self.lo}, {self.hi}]")

    def __add__(self, other: "Interval") -> "Interval":
        return Interval(self.lo + other.lo, self.hi + other.hi)

    def __sub__(self, other: "Interval") -> "Interval":
        return Interval(self.lo - other.hi, self.hi - other.lo)

    def __mul__(self, other: "Interval") -> "Interval":
        corners = [self.lo * other.lo, self.lo * other.hi,
                   self.hi * other.lo, self.hi * other.hi]
        return Interval(min(corners), max(corners))

    def __neg__(self) -> "Interval":
        return Interval(-self.hi, -self.lo)

    def union(self, other: "Interval") -> "Interval":
        return Interval(min(self.lo, other.lo), max(self.hi, other.hi))

    def width_bits(self) -> int:
        """Signed bit width that holds every value in the interval."""
        magnitude = max(abs(self.lo), abs(self.hi))
        return max(2, magnitude.bit_length() + 1)

    def as_tuple(self) -> tuple[int, int]:
        return (self.lo, self.hi)


@dataclass(frozen=True)
class Obligation:
    """One zero-knowledge proof the audit has to carry, derived from the source."""

    kind: str                 # product | range | bit | opening
    target: str
    detail: str
    bits: int = 0

    def as_dict(self) -> dict:
        return {"kind": self.kind, "target": self.target,
                "detail": self.detail, "bits": self.bits}


@dataclass
class Declaration:
    name: str
    interval: Interval
    role: str                 # param | state | input


@dataclass
class Rule:
    name: str
    declarations: dict[str, Declaration]
    outputs: dict[str, ast.Expression]
    source: str
    intervals: dict[str, Interval] = field(default_factory=dict)
    degrees: dict[str, int] = field(default_factory=dict)
    obligations: list[Obligation] = field(default_factory=list)

    def secrets(self) -> list[str]:
        return [d.name for d in self.declarations.values() if d.role in ("param", "state")]

    def inputs(self) -> list[str]:
        return [d.name for d in self.declarations.values() if d.role == "input"]

    def output_interval(self) -> Interval:
        combined = None
        for name in self.outputs:
            interval = self.intervals[name]
            combined = interval if combined is None else combined.union(interval)
        return combined

    def required_bits(self) -> int:
        return self.output_interval().width_bits()

    def summary(self) -> dict:
        return {
            "name": self.name,
            "secrets": self.secrets(),
            "inputs": self.inputs(),
            "outputs": {k: self.intervals[k].as_tuple() for k in self.outputs},
            "max_degree": max(self.degrees.values()) if self.degrees else 0,
            "required_bits": self.required_bits(),
            "obligations": [o.as_dict() for o in self.obligations],
        }


HEADER_ROLES = {"param": "param", "state": "state", "input": "input"}


def parse(source: str, name: str = "policy") -> Rule:
    """Read declarations and output expressions; reject anything outside the subset."""
    declarations: dict[str, Declaration] = {}
    outputs: dict[str, ast.Expression] = {}

    for lineno, raw in enumerate(source.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        head, _, rest = line.partition(" ")
        if head in HEADER_ROLES:
            declarations.update(_parse_declaration(HEADER_ROLES[head], rest, lineno))
            continue
        if "=" not in line:
            raise RuleError(f"line {lineno}: expected a declaration or an assignment")
        target, _, expression = line.partition("=")
        target = target.strip()
        if not target.isidentifier():
            raise RuleError(f"line {lineno}: '{target}' is not a valid output name")
        if target in declarations:
            raise RuleError(f"line {lineno}: '{target}' is already declared")
        try:
            tree = ast.parse(expression.strip(), mode="eval")
        except SyntaxError as exc:
            raise RuleError(f"line {lineno}: cannot parse expression: {exc.msg}") from exc
        outputs[target] = tree

    if not declarations:
        raise RuleError("a rule must declare at least one parameter")
    if not outputs:
        raise RuleError("a rule must produce at least one output")
    return Rule(name=name, declarations=declarations, outputs=outputs, source=source)


_DECLARATION = re.compile(r"([A-Za-z_]\w*)\s*\[\s*(-?\d+)\s*,\s*(-?\d+)\s*\]")


def _parse_declaration(role: str, rest: str, lineno: int) -> dict[str, Declaration]:
    out: dict[str, Declaration] = {}
    matches = list(_DECLARATION.finditer(rest))
    leftover = _DECLARATION.sub("", rest).replace(",", "").strip()
    if leftover:
        raise RuleError(f"line {lineno}: '{leftover}' needs a range, e.g. half[1,200]")
    if not matches:
        raise RuleError(f"line {lineno}: no declarations found")
    for match in matches:
        ident = match.group(1)
        bounds = f"{match.group(2)},{match.group(3)}]"
        if not ident.isidentifier():
            raise RuleError(f"line {lineno}: '{ident}' is not a valid name")
        if ident in FORBIDDEN_INPUTS:
            raise RuleError(
                f"line {lineno}: '{ident}' may not be a pricing input; a quote must not "
                f"depend on who is asking")
        try:
            lo_text, hi_text = bounds[:-1].split(",")
            interval = Interval(int(lo_text), int(hi_text))
        except (ValueError, RuleError) as exc:
            raise RuleError(f"line {lineno}: bad range on '{ident}': {exc}") from exc
        out[ident] = Declaration(ident, interval, role)
    return out


class _Analyser(ast.NodeVisitor):
    """Interval arithmetic, degree tracking and obligation extraction in one pass."""

    def __init__(self, rule: Rule):
        self.rule = rule
        self.obligations: list[Obligation] = []
        self._label = ""

    def analyse(self, label: str, tree: ast.Expression) -> tuple[Interval, int]:
        self._label = label
        return self.visit(tree.body)

    # --- rejection first ---
    def generic_visit(self, node):
        raise RuleError(
            f"'{type(node).__name__}' is not allowed in a price rule; the language has "
            f"no loops, indexing, attributes, calls other than "
            f"{sorted(INTRINSICS)}, or division")

    def visit(self, node):
        if not isinstance(node, ALLOWED_NODES):
            self.generic_visit(node)
        return super().visit(node)

    # --- the allowed forms ---
    def visit_Constant(self, node):
        if not isinstance(node.value, int) or isinstance(node.value, bool):
            raise RuleError("only integer constants are allowed; there is no division "
                            "and no floating point")
        return Interval(node.value, node.value), 0

    def visit_Name(self, node):
        if node.id in FORBIDDEN_INPUTS:
            raise RuleError(f"'{node.id}' may not be used in a price rule")
        declaration = self.rule.declarations.get(node.id)
        if declaration is None:
            raise RuleError(f"'{node.id}' is not declared; a rule may only read its own "
                            f"declared parameters, state and inputs")
        # An input is committed with a fresh blinding and the verifier sees only
        # the commitment, so it is as secret as a parameter and a product that
        # touches it costs a proof. Grading inputs as degree zero said the
        # opposite, and the cost model came out two products short on a rule
        # with two of them --- `test_dsl.py` now pins the plan to the audit.
        degree = 0 if declaration.role == "constant" else 1
        return declaration.interval, degree

    def visit_UnaryOp(self, node):
        interval, degree = self.visit(node.operand)
        return (-interval if isinstance(node.op, ast.USub) else interval), degree

    def visit_BinOp(self, node):
        left, left_degree = self.visit(node.left)
        right, right_degree = self.visit(node.right)
        if isinstance(node.op, ast.Add):
            return left + right, max(left_degree, right_degree)
        if isinstance(node.op, ast.Sub):
            return left - right, max(left_degree, right_degree)
        if isinstance(node.op, ast.Mult):
            degree = left_degree + right_degree
            if degree > 2:
                raise RuleError(
                    "a price rule may not exceed degree two in its secrets; higher "
                    "degree would need a proof per intermediate product")
            if degree == 2:
                # a secret times a secret is the one construct that costs a proof
                self.obligations.append(Obligation(
                    "product", self._label,
                    f"{ast.unparse(node.left)} * {ast.unparse(node.right)}"))
            return left * right, degree
        raise RuleError(f"operator '{type(node.op).__name__}' is not allowed")

    def visit_Compare(self, node):
        if len(node.ops) != 1:
            raise RuleError("chained comparisons are not allowed")
        left, _ = self.visit(node.left)
        right, _ = self.visit(node.comparators[0])
        difference = left - right if isinstance(node.ops[0], (ast.GtE, ast.Gt)) else right - left
        # The order here is the order `RuleProver` emits them, and
        # `test_dsl.py` pins the two together --- a cost model that has drifted
        # from the audit it is costing is worse than no cost model.
        self.obligations.append(Obligation("bit", self._label,
                                           f"result of {ast.unparse(node)}"))
        if isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            # zero test: `bit * difference = 0` and `difference * witness = 1 - bit`
            self.obligations.append(Obligation(
                "product", self._label,
                f"{ast.unparse(node)}: the bit sends the difference to zero"))
            self.obligations.append(Obligation(
                "product", self._label,
                f"{ast.unparse(node)}: the difference is invertible when the bit is 0"))
        else:
            # total comparison: one product for `bit * difference`, then one
            # range proof on `2P - S + B - g`, which covers both answers
            self.obligations.append(Obligation(
                "product", self._label,
                f"{ast.unparse(node)}: the bit against the difference"))
            self.obligations.append(Obligation(
                "range", self._label, ast.unparse(node),
                (difference - Interval(1, 1)).width_bits() + 1))
        return Interval(0, 1), 0

    def visit_BoolOp(self, node):
        if not isinstance(node.op, ast.And):
            raise RuleError("only 'and' is allowed; 'or' would need a disjunction proof")
        for value in node.values:
            interval, _ = self.visit(value)
            if (interval.lo, interval.hi) != (0, 1):
                raise RuleError("'and' may only combine conditions")
        for _ in range(len(node.values) - 1):
            self.obligations.append(Obligation(
                "product", self._label, "conjunction of two conditions"))
        return Interval(0, 1), 0

    def _selection(self, what: str, left: Interval, right: Interval,
                   result: Interval) -> None:
        """What `min`/`max` actually costs, which is not one range and one product.

        `RuleProver._select` proves the result no worse than *each* input --- two
        range proofs, not one --- and then pins it to one of them with a product
        that has to open to zero. The plan counted one range and one product and
        no opening, so a rule with a clamp in it was costed at less than half.
        """
        self.obligations.append(Obligation(
            "range", self._label, f"{what}: not worse than the first",
            (left - result).width_bits()))
        self.obligations.append(Obligation(
            "range", self._label, f"{what}: not worse than the second",
            (right - result).width_bits()))
        self.obligations.append(Obligation(
            "product", self._label, f"{what}: pinned to one of its inputs"))
        self.obligations.append(Obligation(
            "equality", self._label, f"{what}: the pin opens to zero"))

    def visit_Call(self, node):
        if not isinstance(node.func, ast.Name) or node.func.id not in INTRINSICS:
            raise RuleError(f"only {sorted(INTRINSICS)} may be called")
        parts = [self.visit(argument) for argument in node.args]
        name = node.func.id
        if name in ("min", "max"):
            if len(parts) != 2:
                raise RuleError(f"{name} takes exactly two arguments")
            (a, da), (b, db) = parts
            merged = Interval(min(a.lo, b.lo), min(a.hi, b.hi)) if name == "min" else \
                Interval(max(a.lo, b.lo), max(a.hi, b.hi))
            self._selection(name, a, b, merged)
            return merged, max(da, db)
        if name == "clamp":
            if len(parts) != 3:
                raise RuleError("clamp takes a value and two bounds")
            (value, degree), (lo, _), (hi, _) = parts
            if lo.lo != lo.hi or hi.lo != hi.hi:
                raise RuleError("clamp bounds must be constants so the range is static")
            lowered = Interval(max(value.lo, lo.lo), max(value.hi, lo.hi))
            self._selection("clamp lower bound", value, lo, lowered)
            clamped = Interval(min(lowered.lo, hi.lo), min(lowered.hi, hi.hi))
            self._selection("clamp upper bound", lowered, hi, clamped)
            return Interval(lo.lo, hi.hi), degree
        if name == "signed":
            if len(parts) != 2:
                raise RuleError("signed takes a side bit and a magnitude")
            (side, _), (magnitude, degree) = parts
            if (side.lo, side.hi) != (0, 1):
                raise RuleError("the first argument of signed must be a condition")
            self.obligations.append(Obligation("product", self._label, "signed selection"))
            return Interval(-magnitude.hi, magnitude.hi), degree
        raise RuleError(f"unknown intrinsic {name}")


def check(rule: Rule) -> Rule:
    """Run every static check and fill in the derived facts."""
    analyser = _Analyser(rule)
    for label, tree in rule.outputs.items():
        interval, degree = analyser.analyse(label, tree)
        rule.intervals[label] = interval
        rule.degrees[label] = degree
    # the declared bounds themselves are proof obligations at registration time
    for declaration in rule.declarations.values():
        if declaration.role in ("param", "state"):
            rule.obligations.append(Obligation(
                "range", declaration.name,
                f"{declaration.name} in [{declaration.interval.lo}, {declaration.interval.hi}]",
                (declaration.interval.hi - declaration.interval.lo).bit_length() or 1))
    rule.obligations.extend(analyser.obligations)

    # A parameter that is declared and never read is either dead weight or a
    # channel for something the rule is not supposed to carry. Either way the
    # registry should not be asked to hold it.
    read = {node.id for tree in rule.outputs.values()
            for node in ast.walk(tree) if isinstance(node, ast.Name)}
    unused = sorted(set(rule.declarations) - read)
    if unused:
        raise RuleError(
            f"declared but never used: {unused}; a rule may not register values "
            f"it does not price with")
    return rule


def compile_rule(source: str, name: str = "policy") -> Rule:
    return check(parse(source, name))
