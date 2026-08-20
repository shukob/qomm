"""The two host tables are one table.

`scripts/hosts.py` and `rust/qomm-measure/src/hosts.rs` both map a machine's
real name to the label that goes into an artifact. Two copies exist because a
Rust harness cannot import Python and a harness that cannot label its host will
record the real one. The copies are only safe while they agree, so this reads
both and says so when they stop.
"""

from __future__ import annotations

import re
from pathlib import Path

from scripts.hosts import LABELS, label

RUST = Path(__file__).resolve().parent.parent / "rust" / "qomm-measure" / "src" / "hosts.rs"
ENTRY = re.compile(r'\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)')


def rust_labels() -> dict[str, str]:
    source = RUST.read_text(encoding="utf-8")
    start = source.index("pub const LABELS")
    end = source.index("];", start)
    return dict(ENTRY.findall(source[start:end]))


def test_the_tables_hold_the_same_machines():
    assert rust_labels() == LABELS


def test_every_name_gets_the_same_label_from_both():
    # The lookups differ in shape --- Python falls back to the short name, Rust
    # compares both forms --- so agreeing on the table is not by itself agreeing
    # on the answer.
    names = list(LABELS) + [n.split(".")[0] for n in LABELS] + [
        "host-a.internal", "somebody-elses-laptop", "unknown.example.com"]
    table = rust_labels()

    def rust_label(node: str) -> str:
        short = node.split(".")[0]
        for name, published in table.items():
            if name in (node, short):
                return published
        return node

    for node in names:
        assert rust_label(node) == label(node), node
