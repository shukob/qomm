"""The notebooks must at least be loadable and consistent with the API they use.

Executing them is a separate target (`make notebooks`) because it takes minutes
and the suite should stay under a minute. What is checked here is the failure
that actually happens to notebooks --- they call something that has been renamed
and nobody notices, because nobody ran them.
"""

import ast
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

NOTEBOOKS = sorted((ROOT / "notebooks").glob("*.ipynb"))


def code_cells(path: Path):
    nb = json.loads(path.read_text())
    for cell in nb["cells"]:
        if cell["cell_type"] == "code":
            yield "".join(cell["source"])


@pytest.mark.parametrize("path", NOTEBOOKS, ids=lambda p: p.name)
def test_the_notebook_is_wellformed(path):
    nb = json.loads(path.read_text())
    assert nb["cells"], f"{path.name} has no cells"
    assert all("id" in cell for cell in nb["cells"])
    assert all(cell["cell_type"] in ("code", "markdown") for cell in nb["cells"])


@pytest.mark.parametrize("path", NOTEBOOKS, ids=lambda p: p.name)
def test_every_code_cell_parses(path):
    for index, source in enumerate(code_cells(path)):
        # shell escapes and line magics are IPython, not Python
        cleaned = "\n".join(line for line in source.splitlines()
                            if not line.lstrip().startswith(("!", "%")))
        try:
            ast.parse(cleaned)
        except SyntaxError as exc:
            pytest.fail(f"{path.name} code cell {index}: {exc}")


@pytest.mark.parametrize("path", NOTEBOOKS, ids=lambda p: p.name)
def test_it_only_calls_functions_that_exist(path):
    """The failure mode notebooks actually have: a renamed helper."""
    from qomm_sim import lab

    used = set()
    for source in code_cells(path):
        cleaned = "\n".join(line for line in source.splitlines()
                            if not line.lstrip().startswith(("!", "%")))
        for node in ast.walk(ast.parse(cleaned)):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                    and node.value.id == "lab":
                used.add(node.attr)
    missing = sorted(name for name in used if not hasattr(lab, name))
    assert not missing, f"{path.name} calls lab.{missing} which does not exist"


def test_the_experiment_notebook_exists_and_uses_the_bench():
    path = ROOT / "notebooks" / "experiment.ipynb"
    assert path.exists()
    body = path.read_text()
    assert "lab.build" in body and "lab.arm" in body, \
        "the interactive notebook should drive the simulation, not only read artifacts"
