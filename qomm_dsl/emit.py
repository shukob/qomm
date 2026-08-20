"""Emit the three artifacts a checked rule implies: circuit, evaluator, obligations.

They come from the same source, so they cannot drift apart. That is the practical
reason to have a language here: the audit is a compiler output, and a rule that
changes changes its own audit with it.
"""

from __future__ import annotations

import ast
from typing import Any, Mapping

from .language import INTRINSICS, Obligation, Rule, RuleError

# MP-SPDZ works on secret vectors; every declared name is one column.
_MPC_INTRINSIC = {
    "min": "({a}).__lt__({b}).if_else({a}, {b})",
    "max": "({a}).__lt__({b}).if_else({b}, {a})",
}


def to_mpc(rule: Rule, vector: bool = True) -> dict[str, str]:
    """One MP-SPDZ expression per output, over the declared columns."""
    return {name: _emit_mpc(tree.body) for name, tree in rule.outputs.items()}


def _emit_mpc(node: ast.AST) -> str:
    if isinstance(node, ast.Constant):
        return f"sint({node.value})" if not isinstance(node.value, bool) else str(int(node.value))
    if isinstance(node, ast.Name):
        return f"col_{node.id}"
    if isinstance(node, ast.UnaryOp):
        inner = _emit_mpc(node.operand)
        return f"(-{inner})" if isinstance(node.op, ast.USub) else inner
    if isinstance(node, ast.BinOp):
        left, right = _emit_mpc(node.left), _emit_mpc(node.right)
        symbol = {ast.Add: "+", ast.Sub: "-", ast.Mult: "*"}[type(node.op)]
        return f"({left} {symbol} {right})"
    if isinstance(node, ast.Compare):
        left, right = _emit_mpc(node.left), _emit_mpc(node.comparators[0])
        symbol = {ast.LtE: "<=", ast.Lt: "<", ast.GtE: ">=", ast.Gt: ">",
                  ast.Eq: "==", ast.NotEq: "!="}[type(node.ops[0])]
        return f"({left} {symbol} {right})"
    if isinstance(node, ast.BoolOp):
        return "(" + " * ".join(_emit_mpc(v) for v in node.values) + ")"
    if isinstance(node, ast.Call):
        name = node.func.id
        args = [_emit_mpc(a) for a in node.args]
        if name in _MPC_INTRINSIC:
            return _MPC_INTRINSIC[name].format(a=args[0], b=args[1])
        if name == "clamp":
            value, lo, hi = args
            return (f"(({value}).__lt__({lo}).if_else({lo}, "
                    f"({hi}).__lt__({value}).if_else({hi}, {value})))")
        if name == "signed":
            side, magnitude = args
            return f"({side}).if_else(-{magnitude}, {magnitude})"
    raise RuleError(f"cannot emit MP-SPDZ for {type(node).__name__}")


def evaluate(rule: Rule, bindings: Mapping[str, int]) -> dict[str, int]:
    """Cleartext reference. Used to check the circuit and the proof agree."""
    missing = [name for name in rule.declarations if name not in bindings]
    if missing:
        raise RuleError(f"missing values for {missing}")
    return {name: _eval(tree.body, bindings) for name, tree in rule.outputs.items()}


def _eval(node: ast.AST, env: Mapping[str, int]) -> int:
    if isinstance(node, ast.Constant):
        return int(node.value)
    if isinstance(node, ast.Name):
        return int(env[node.id])
    if isinstance(node, ast.UnaryOp):
        value = _eval(node.operand, env)
        return -value if isinstance(node.op, ast.USub) else value
    if isinstance(node, ast.BinOp):
        left, right = _eval(node.left, env), _eval(node.right, env)
        return {ast.Add: left + right, ast.Sub: left - right,
                ast.Mult: left * right}[type(node.op)]
    if isinstance(node, ast.Compare):
        left, right = _eval(node.left, env), _eval(node.comparators[0], env)
        return int({ast.LtE: left <= right, ast.Lt: left < right,
                    ast.GtE: left >= right, ast.Gt: left > right,
                    ast.Eq: left == right, ast.NotEq: left != right}[type(node.ops[0])])
    if isinstance(node, ast.BoolOp):
        result = 1
        for value in node.values:
            result *= _eval(value, env)
        return result
    if isinstance(node, ast.Call):
        name = node.func.id
        args = [_eval(a, env) for a in node.args]
        if name == "min":
            return min(args[0], args[1])
        if name == "max":
            return max(args[0], args[1])
        if name == "clamp":
            return max(args[1], min(args[2], args[0]))
        if name == "signed":
            return -args[1] if args[0] else args[1]
    raise RuleError(f"cannot evaluate {type(node).__name__}")


def obligation_plan(rule: Rule) -> dict:
    """Group the derived obligations so the audit can be costed before it is run."""
    counts: dict[str, int] = {}
    range_bits: list[int] = []
    for obligation in rule.obligations:
        counts[obligation.kind] = counts.get(obligation.kind, 0) + 1
        if obligation.kind == "range":
            range_bits.append(obligation.bits)
    return {
        "counts": counts,
        "total": len(rule.obligations),
        "range_bits": sorted(range_bits),
        "total_bit_proofs": sum(range_bits) + counts.get("bit", 0),
        "required_circuit_bits": rule.required_bits(),
        "output_intervals": {k: v.as_tuple() for k, v in rule.intervals.items()},
    }
