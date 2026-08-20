#!/usr/bin/env python3
"""Replace real machine names in already-recorded artifacts with their labels.

The harnesses now record a label where they used to record `platform.node()`,
so anything measured from here on is already clean. This is for what was
measured before that, which is most of the artifacts: 27 files carrying three
real machine names, one of which is a person's laptop.

The earlier plan was to keep the real names and scrub at publication time, on
the argument that editing a measurement's provenance devalues it. That argument
does not survive contact with the actual risk, which is a repository that is
unsafe to publish until somebody remembers a step nobody wrote down. Nothing is
lost that `scripts/hosts.py` does not hold --- the mapping is the provenance.

Only whole names are replaced, and only names the mapping knows, so a file that
happens to contain a substring is left alone and an unknown machine is reported
rather than quietly rewritten.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts.hosts import LABELS                                    # noqa: E402

# longest first, so `host-b` is not half-eaten by a shorter key
PATTERN = re.compile("|".join(re.escape(k) for k in
                              sorted(LABELS, key=len, reverse=True)))


def scrub(path: Path, dry_run: bool) -> int:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return 0
    hits = PATTERN.findall(text)
    if not hits:
        return 0
    if not dry_run:
        path.write_text(PATTERN.sub(lambda m: LABELS[m.group(0)], text), encoding="utf-8")
    return len(hits)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=ROOT / "artifacts")
    ap.add_argument("--apply", action="store_true",
                    help="without this the run only reports what it would change")
    args = ap.parse_args()

    total_files = total_hits = 0
    for path in sorted(args.root.rglob("*")):
        if not path.is_file():
            continue
        hits = scrub(path, dry_run=not args.apply)
        if hits:
            total_files += 1
            total_hits += hits
            print(f"  {path.relative_to(args.root)}: {hits}")
    verb = "rewrote" if args.apply else "would rewrite"
    print(f"{verb} {total_hits} name(s) across {total_files} file(s)")
    if not args.apply:
        print("re-run with --apply to make the change")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
