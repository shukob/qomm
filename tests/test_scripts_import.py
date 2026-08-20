"""Every script must at least start.

A host-label change added a project import to six harnesses; five already put
the repository root on the path and one did not, so `run_qomm.py` -- the MPC
runner everything else depends on -- raised ModuleNotFoundError on every
invocation. Nothing in the suite touched it, because the suite tests libraries
and the scripts are only ever run by hand. This is the cheapest check that would
have caught it: import each one and see that it survives.
"""

import runpy
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = sorted(p for p in (ROOT / "scripts").glob("*.py") if p.name != "__init__.py")


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_the_script_starts(script):
    """`--help` exercises imports and argument parsing and touches nothing else."""
    result = subprocess.run([sys.executable, str(script), "--help"],
                            capture_output=True, text=True, cwd=ROOT, timeout=120)
    combined = result.stdout + result.stderr
    assert "ModuleNotFoundError" not in combined, combined[-600:]
    assert "ImportError" not in combined, combined[-600:]
    assert "SyntaxError" not in combined, combined[-600:]
