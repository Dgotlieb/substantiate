"""Test package.

Puts ``src/`` on the path so the suite runs from a clean checkout with no
install step and no dependencies:

    python3 -m unittest discover -s tests -t .
"""

import pathlib
import sys

_SRC = pathlib.Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text()
