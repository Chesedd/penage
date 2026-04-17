from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Rewrite asserts in support modules so ``assert actual == expected`` in the
# golden-trace harness gets pytest's structural dict/list diff instead of a
# bare AssertionError string.
pytest.register_assert_rewrite("tests.support.golden_trace")
