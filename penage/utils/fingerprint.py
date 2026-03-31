from __future__ import annotations

import json
from typing import Any

from penage.core.actions import Action


def action_fingerprint(action: Action) -> str:
    params_json = json.dumps(action.params, sort_keys=True, ensure_ascii=False, default=str)
    return f"{action.type.value}:{params_json}"