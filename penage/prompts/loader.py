from __future__ import annotations

from pathlib import Path


def load_prompt(name: str) -> str:
    """Load a prompt template by short name.

    Reads ``penage/prompts/{name}.md`` relative to this file.
    Raises ``FileNotFoundError`` with a clear message if the prompt is missing.
    """
    path = Path(__file__).parent / f"{name}.md"
    if not path.is_file():
        raise FileNotFoundError(f"Prompt '{name}' not found at {path}")
    return path.read_text(encoding="utf-8")
