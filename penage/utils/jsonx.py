from __future__ import annotations

import json
from typing import Any, Dict, Optional

from penage.llm.ollama import extract_first_json_object


def parse_json_object(text: str) -> Optional[Dict[str, Any]]:
    return extract_first_json_object(text)


def dumps_pretty(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)