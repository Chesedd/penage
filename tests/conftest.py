from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Enable pytest assertion rewriting for helper modules so mismatches surface
# the per-element dict/list diff rather than a bare ``AssertionError``.
pytest.register_assert_rewrite("tests.support.golden_trace")