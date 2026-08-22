"""A local that quietly takes over a name the function still needs.

This bug shape has landed three times in this repository and cost an afternoon
each time. In the document generator a loop variable named `ms` took over the
formatting helper; then one named `label`; then in the exporter a
`for held in (...)` took over the `held` that was holding the preserved
Cargo.lock, so the lock was written as a string and the export died.

None of them is a typo and none is caught by reading, because the two uses are
usually far apart. They are all one pattern: a name is bound, a loop rebinds it,
and something after the loop reads it expecting the first binding. That is what
this checks --- across the scripts, not in one of them, since the point is that
it keeps happening somewhere new.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SCANNED = sorted((ROOT / "scripts").glob("*.py")) + sorted((ROOT / "mp_spdz").glob("*.py"))


def _names(node) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [n for element in node.elts for n in _names(element)]
    return []


def _span(node) -> tuple[int, int]:
    first = getattr(node, "lineno", 0)
    return first, max((getattr(inner, "lineno", first) for inner in ast.walk(node)),
                      default=first)


def _rebinding_spans(function, name: str) -> list[tuple[int, int]]:
    """Where the name means something else: another loop, or a comprehension.

    Comprehensions matter as much as loops here. `[r for r in rows]` binds its
    own `r` in its own scope, so a read inside one is not a read of the
    function's `r` --- and treating it as one is what made the first version of
    this check report five things that were all fine.
    """
    spans = []
    for node in ast.walk(function):
        if isinstance(node, (ast.For, ast.AsyncFor)) and name in _names(node.target):
            spans.append(_span(node))
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp,
                             ast.GeneratorExp)):
            if any(name in _names(gen.target) for gen in node.generators):
                spans.append(_span(node))
    return spans


def _reads_after(function, name: str, line: int) -> int | None:
    """The first line after `line` that reads `name` expecting the old binding.

    Reads inside a later loop that binds the same name do not count: reusing a
    short name as the variable of several successive loops is idiomatic and is
    not the bug. What is the bug is a read that is not covered by any loop's own
    binding, because that read wanted the value from before.
    """
    spans = _rebinding_spans(function, name)
    for node in function.body:
        for inner in ast.walk(node):
            if not (isinstance(inner, ast.Name) and inner.id == name
                    and isinstance(inner.ctx, ast.Load)):
                continue
            at = getattr(inner, "lineno", 0)
            if at <= line:
                continue
            if any(start <= at <= end for start, end in spans):
                continue
            return at
    return None


def _offences(tree: ast.AST) -> list[tuple[str, str, int, int]]:
    found = []
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        bound: dict[str, int] = {}
        for node in ast.walk(function):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    for name in _names(target):
                        bound.setdefault(name, node.lineno)
        for node in ast.walk(function):
            if not isinstance(node, (ast.For, ast.AsyncFor)):
                continue
            end = max((getattr(inner, "lineno", node.lineno)
                       for inner in ast.walk(node)), default=node.lineno)
            for name in _names(node.target):
                first = bound.get(name)
                if first is None or first >= node.lineno:
                    continue
                read = _reads_after(function, name, end)
                if read is not None:
                    found.append((function.name, name, node.lineno, read))
    return found


def test_no_loop_variable_takes_over_a_name_the_function_still_needs():
    offences = []
    for path in SCANNED:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:                                   # pragma: no cover
            continue
        for function, name, loop_line, read_line in _offences(tree):
            offences.append(
                f"{path.relative_to(ROOT)}:{loop_line} in {function}(): the loop "
                f"variable `{name}` takes over a name bound earlier and read "
                f"again at line {read_line}")
    assert not offences, (
        "a loop variable is shadowing a name the function still needs:\n  "
        + "\n  ".join(offences))


def test_the_check_catches_the_shape_it_is_for():
    """The exporter's bug, reduced. Without this the test above proves nothing."""
    source = """
def export():
    held = read_bytes()
    for held in ("host", "rustc"):
        record[held] = 1
    write(held)
"""
    offences = _offences(ast.parse(source))
    assert [(f, n) for f, n, _, _ in offences] == [("export", "held")]


def test_the_check_does_not_fire_on_a_loop_variable_used_only_inside():
    source = """
def fine():
    total = 0
    for item in things:
        total += item
    return total
"""
    assert _offences(ast.parse(source)) == []
