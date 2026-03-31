from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from penage.core.actions import Action, ActionType
from penage.core.candidates import CandidateAction
from penage.core.state import State
from penage.specialists.base import SpecialistConfig


def _find_form_with_field(forms: List[Dict[str, Any]], field_name: str) -> Optional[Dict[str, Any]]:
    for f in forms or []:
        inputs = f.get("inputs") or []
        for inp in inputs:
            if (inp.get("name") or "") == field_name:
                return f
    return None


def _has_field(form: Dict[str, Any], field_name: str) -> bool:
    for inp in (form.get("inputs") or []):
        if (inp.get("name") or "") == field_name:
            return True
    return False


@dataclass(slots=True)
class LoginWorkflowSpecialist:
    name: str = "login_workflow"
    default_username: str = "test"
    default_password: str = "test"

    def propose(self, state: State, *, config: SpecialistConfig) -> List[CandidateAction]:
        forms = state.last_forms or []
        if not forms:
            return []

        pw_form = _find_form_with_field(forms, "password")
        if pw_form and not state.facts.get("login_workflow_password_tried"):
            action_url = str(pw_form.get("action") or state.last_http_url or "")
            if action_url:
                a = Action(
                    type=ActionType.HTTP,
                    params={"method": "POST", "url": action_url, "data": {"password": self.default_password}},
                    timeout_s=30,
                    tags=["login", "workflow", "password-step"],
                )
                return [
                    CandidateAction(
                        action=a,
                        source=self.name,
                        score=10.0,
                        cost=1.0,
                        reason="Detected password form; submit default password (hidden fields auto-filled).",
                    )
                ]

        user_form = _find_form_with_field(forms, "username")
        if user_form and not _has_field(user_form, "password") and not state.facts.get("login_workflow_username_tried"):
            action_url = str(user_form.get("action") or state.last_http_url or "")
            if action_url:
                a = Action(
                    type=ActionType.HTTP,
                    params={"method": "POST", "url": action_url, "data": {"username": self.default_username}},
                    timeout_s=30,
                    tags=["login", "workflow", "username-step"],
                )
                return [
                    CandidateAction(
                        action=a,
                        source=self.name,
                        score=9.0,
                        cost=1.0,
                        reason="Detected username-only login form; submit default username.",
                    )
                ]

        return []