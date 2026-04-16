from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

_JSON_FENCE_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)

_JSON_HINTS = (
    "return only json",
    "return only a json object",
    "return json",
    "output schema",
    "\"actions\"",
    "'actions'",
    "valid json object",
)


def extract_first_json_object(text: str) -> Optional[Dict[str, Any]]:
    """Extract the first JSON object from a (possibly markdown-wrapped) LLM response."""
    m = _JSON_FENCE_RE.search(text)
    if m:
        candidate = m.group(1)
        try:
            return json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            return None

    if "{" in text and "}" in text:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = text[start : end + 1]
            try:
                return json.loads(candidate)
            except (json.JSONDecodeError, ValueError):
                return None
    return None


def should_force_json(content_joined: str) -> bool:
    low = content_joined.lower()
    return any(h in low for h in _JSON_HINTS)
