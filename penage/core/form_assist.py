from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from penage.core.actions import Action, ActionType
from penage.core.state import State


@dataclass(slots=True)
class FormAssist:

    def normalize_http_post(self, action: Action, st: State) -> Action:
        if action.type != ActionType.HTTP:
            return action

        method = str((action.params or {}).get("method") or "GET").upper()
        if method != "POST":
            return action

        params = dict(action.params or {})
        qparams = params.get("params")
        data = params.get("data")
        if data is None:
            data = {}
        if isinstance(qparams, dict) and isinstance(data, dict) and not data and qparams:
            low_keys = {str(k).lower() for k in qparams.keys()}
            formish = bool(
                low_keys & {"username", "password", "email", "csrf", "csrf_token", "csrfmiddlewaretoken", "token",
                            "user_id"})
            if formish or len(qparams) >= 2:
                params["data"] = dict(qparams)
                params["params"] = {}
                data = params["data"]

        data = params.get("data")

        if data is None:
            data = {}
        if not isinstance(data, dict):
            return action

        form = self._choose_form_for_action(action, st)
        if not form:
            return action

        inputs = form.get("inputs") or []
        for inp in inputs:
            name = inp.get("name")
            if not name:
                continue

            value = inp.get("value")
            is_hidden = bool(inp.get("hidden"))
            is_required = bool(inp.get("required"))

            if name not in data and value is not None and (is_hidden or value != ""):
                data[name] = value

            if name not in data and is_required:
                data[name] = ""

        params["data"] = data
        return Action(type=action.type, params=params, timeout_s=action.timeout_s, tags=action.tags)

    def _choose_form_for_action(self, action: Action, st: State) -> Optional[Dict[str, Any]]:
        action_url = str((action.params or {}).get("url") or "")

        forms_by_url = getattr(st, "forms_by_url", None)
        if action_url and isinstance(forms_by_url, dict):
            remembered = forms_by_url.get(action_url)
            if remembered:
                return remembered[0]

        action_path = ""
        if action_url:
            try:
                action_path = urlparse(action_url).path
            except Exception:
                action_path = ""

        if action_path and isinstance(forms_by_url, dict):
            for _page_url, forms in forms_by_url.items():
                for f in forms or []:
                    f_action = str(f.get("action") or "")
                    if not f_action:
                        continue
                    try:
                        if urlparse(f_action).path == action_path:
                            return f
                    except Exception:
                        continue

        if not st.last_forms:
            return None

        if action_path:
            for f in st.last_forms:
                f_action = str(f.get("action") or "")
                if not f_action:
                    continue
                try:
                    if urlparse(f_action).path == action_path:
                        return f
                except Exception:
                    continue

        return st.last_forms[0]