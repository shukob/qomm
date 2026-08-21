#!/usr/bin/env python3
"""One record of what every artifact is, and a check that it still is.

The paper says every number in it is generated from `artifacts/` and none of
them retyped by hand. That is a claim about a process, and a claim about a
process needs something that fails when the process did not run. This is that
thing: a manifest of every artifact with its SHA-256, its size, the host it
records, and the commit the tree was on when it was written --- and a `--check`
that recomputes the hashes and exits non-zero if any of them moved.

It does not check that the prose agrees with the artifacts. It checks that the
artifacts a reader downloads are the artifacts the numbers were taken from,
which is the half that can be checked mechanically.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = ROOT / "artifacts"
MANIFEST = ARTIFACTS / "MANIFEST.json"

# Big generated tapes and figures are outputs, not measurements; the manifest
# covers what a number can be traced to.
SKIP_SUFFIXES = {".pdf", ".png", ".csv"}
SKIP_NAMES = {"MANIFEST.json"}


def commit() -> str | None:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def entries() -> dict[str, dict]:
    found: dict[str, dict] = {}
    for path in sorted(ARTIFACTS.rglob("*")):
        if not path.is_file() or path.suffix in SKIP_SUFFIXES:
            continue
        if path.name in SKIP_NAMES or "figures" in path.parts or "tapes" in path.parts:
            continue
        raw = path.read_bytes()
        record = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
        if path.suffix == ".json":
            try:
                loaded = json.loads(raw)
            except json.JSONDecodeError:
                record["unreadable"] = True
                loaded = None
            if isinstance(loaded, dict):
                for field in ("host", "rustc", "python", "runtime", "target", "group"):
                    if field in loaded:
                        record[field] = loaded[field]
                rows = next((loaded[k] for k in ("rows", "scaling", "chains")
                             if isinstance(loaded.get(k), list)), None)
                if rows is not None:
                    record["rows"] = len(rows)
                    if not rows:
                        # the honest kind of gap: an artifact that exists and
                        # carries nothing, which is what a claim resting on it
                        # is worth
                        record["empty"] = True
        found[str(path.relative_to(ARTIFACTS))] = record
    return found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="compare the tree against the manifest and fail on drift")
    args = ap.parse_args()

    current = entries()
    if not args.check:
        MANIFEST.write_text(json.dumps(
            {"commit": commit(), "artifacts": current}, indent=2, sort_keys=True) + "\n")
        empty = [name for name, r in current.items() if r.get("empty")]
        unlabelled = [name for name, r in current.items()
                      if name.endswith(".json") and "host" not in r]
        print(f"wrote {MANIFEST.relative_to(ROOT)}: {len(current)} artifacts")
        if empty:
            print(f"  {len(empty)} carry no rows, so nothing may be quoted from "
                  f"them: {', '.join(sorted(empty))}")
        if unlabelled:
            # Not stamped after the fact: which machine an old artifact came
            # from is not something to guess, and a guessed label is worse than
            # none. The runners record it now, so the list shrinks as each is
            # regenerated.
            print(f"  {len(unlabelled)} carry no host label, having been written "
                  f"before their runner recorded one: {', '.join(sorted(unlabelled))}")
        return 0

    if not MANIFEST.exists():
        print(f"{MANIFEST} is missing; run `make manifest`.", file=sys.stderr)
        return 1
    recorded = json.loads(MANIFEST.read_text())["artifacts"]
    problems = []
    for name, record in sorted(recorded.items()):
        if name not in current:
            problems.append(f"{name}: in the manifest and not in the tree")
        elif current[name]["sha256"] != record["sha256"]:
            problems.append(f"{name}: changed since the manifest was written")
    for name in sorted(set(current) - set(recorded)):
        problems.append(f"{name}: in the tree and not in the manifest")
    for line in problems:
        print(line, file=sys.stderr)
    if problems:
        print(f"\n{len(problems)} artifact(s) do not match the manifest. Either "
              "re-run the measurement the paper quotes or re-write the manifest, "
              "and say which in the commit.", file=sys.stderr)
        return 1
    print(f"{len(recorded)} artifacts match the manifest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
