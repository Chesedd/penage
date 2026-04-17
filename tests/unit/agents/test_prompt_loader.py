from __future__ import annotations

import pytest

from penage.prompts.loader import load_prompt


def test_load_prompt_coordinator_has_header() -> None:
    text = load_prompt("coordinator")
    assert "# Coordinator agent system prompt" in text


def test_load_prompt_missing_raises() -> None:
    with pytest.raises(FileNotFoundError):
        load_prompt("nonexistent")
