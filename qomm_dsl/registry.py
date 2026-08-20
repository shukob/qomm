"""Registered rule digests, so a substituted price rule is detectable.

Issue #129 asks that an approved rule form and its circuit digest be registered,
with only the secret parameters replaceable afterwards. The DSL makes that a
one-line property: the digest covers the canonical source, the declared bounds
and the emitted circuit, but not the values. Swapping a parameter keeps the
digest; swapping the rule does not.

That covers the rule and stops at the rule, which is the half that was missing.
What the computing nodes execute is not a rule, it is an MP-SPDZ program emitted
from one and then compiled; a node holding the approved digest can still compile
something else, and the registry would never know. So a second digest covers the
emitted program text, and the two are registered together with the circuit shape
they belong to. Approving a rule and then running a different circuit now
requires the shape or the program to differ, and both are checked before the
compiler is invoked rather than after the answers are out.

Deliberately not claimed: this binds the program text the nodes were given, not
the bytecode their compiler produced. Hashing the bytecode would bind that too
and is a one-line extension, but it makes the registered digest depend on the
compiler version, so what it would actually detect is upgrades rather than
substitutions. Where that trade lands is a deployment decision, not one this
module should make silently.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .emit import to_mpc
from .language import Rule, compile_rule

DOMAIN = b"QOMM:RULE-REGISTRY:v1"


def canonical(rule: Rule) -> bytes:
    """Everything that must not change: the shape, the bounds, the circuit."""
    body = {
        "name": rule.name,
        "declarations": {name: [d.role, d.interval.lo, d.interval.hi]
                         for name, d in sorted(rule.declarations.items())},
        "outputs": {name: expression for name, expression in sorted(to_mpc(rule).items())},
        "required_bits": rule.required_bits(),
        "max_degree": max(rule.degrees.values()) if rule.degrees else 0,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def rule_digest(rule: Rule) -> str:
    return hashlib.sha256(DOMAIN + canonical(rule)).hexdigest()


@dataclass(frozen=True)
class ApprovedRule:
    name: str
    digest: str
    required_bits: int
    source: str


class RuleRegistry:
    """The venue's list of approved rule forms."""

    def __init__(self) -> None:
        self._approved: dict[str, ApprovedRule] = {}

    def approve(self, source: str, name: str) -> ApprovedRule:
        rule = compile_rule(source, name)
        entry = ApprovedRule(name, rule_digest(rule), rule.required_bits(), source)
        self._approved[entry.digest] = entry
        return entry

    def check(self, source: str, name: str, claimed_digest: str) -> tuple[bool, str]:
        """Reject a rule that is not the approved one, or a mislabelled digest."""
        if claimed_digest not in self._approved:
            return False, "the claimed digest is not an approved rule form"
        rule = compile_rule(source, name)
        actual = rule_digest(rule)
        if actual != claimed_digest:
            return False, ("the rule does not hash to the digest it claims; "
                           "the registered form was substituted")
        return True, "ok"


PROGRAM_DOMAIN = b"QOMM:PROGRAM-DIGEST:v1"


def program_digest(source: str) -> str:
    """Digest of the emitted MP-SPDZ program text.

    Normalised for whitespace at the ends of lines and for a trailing newline,
    because those differ between generators and editors without changing a
    single instruction, and a digest that trips on them would be turned off.
    """
    body = "\n".join(line.rstrip() for line in source.strip().splitlines())
    return hashlib.sha256(PROGRAM_DOMAIN + body.encode()).hexdigest()


@dataclass(frozen=True)
class ApprovedCircuit:
    """A rule, the program emitted from it, and the shape they were approved for.

    The shape is part of the identity because one rule emits different circuits
    for different maker counts or bit widths, and a node asked for one shape
    must not answer with another.
    """

    name: str
    rule_digest: str
    program_digest: str
    shape: tuple

    def matches(self, source: str, shape: tuple) -> tuple[bool, str]:
        if tuple(shape) != tuple(self.shape):
            return False, (f"circuit shape {tuple(shape)} was never approved for "
                           f"{self.name}; the approved shape is {tuple(self.shape)}")
        actual = program_digest(source)
        if actual != self.program_digest:
            return False, (f"the program for {self.name} does not match what was "
                           f"approved: {actual[:16]} against {self.program_digest[:16]}")
        return True, "ok"


class CircuitRegistry:
    """What each shape is allowed to compile, checked before the compiler runs."""

    def __init__(self) -> None:
        self._approved: dict[tuple, ApprovedCircuit] = {}

    def approve(self, name: str | None, rule_source: str, program_source: str,
                shape: tuple) -> ApprovedCircuit:
        from .language import compile_rule

        rule = compile_rule(rule_source) if name is None else compile_rule(rule_source, name)
        entry = ApprovedCircuit(
            name=rule.name,
            rule_digest=rule_digest(rule),
            program_digest=program_digest(program_source),
            shape=tuple(shape),
        )
        self._approved[tuple(shape)] = entry
        return entry

    def check(self, program_source: str, shape: tuple) -> tuple[bool, str]:
        entry = self._approved.get(tuple(shape))
        if entry is None:
            return False, f"no circuit is approved for shape {tuple(shape)}"
        return entry.matches(program_source, shape)

    def approved_shapes(self) -> list[tuple]:
        return sorted(self._approved)
