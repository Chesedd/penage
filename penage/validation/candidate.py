from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from penage.core.actions import Action
from penage.core.observations import Observation


_EXCERPT_CAP = 2000
_SENSITIVE_SNAPSHOT_KEYS = ("cookies", "cookie", "session", "auth_headers", "api_key")


def _truncate(value: Any, cap: int = _EXCERPT_CAP) -> Any:
    if isinstance(value, str) and len(value) > cap:
        return value[:cap]
    return value


def _scrub_observation_data(data: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of the observation data suitable for an LLM prompt.

    Drops the full page body (``text_full``) and caps excerpts. Keeps
    structural fields (``status_code``, ``url``, ``headers``) useful for
    the validator's reasoning.
    """
    scrubbed: dict[str, Any] = {}
    for key, value in data.items():
        if key == "text_full":
            continue
        if key in ("text_excerpt", "text"):
            scrubbed[key] = _truncate(value)
            continue
        scrubbed[key] = value
    return scrubbed


def _scrub_state_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    scrubbed: dict[str, Any] = {}
    for key, value in snapshot.items():
        if key in _SENSITIVE_SNAPSHOT_KEYS:
            continue
        if key == "last_http_excerpt":
            scrubbed[key] = _truncate(value)
            continue
        if key == "last_http_text_full":
            continue
        scrubbed[key] = value
    return scrubbed


@dataclass(frozen=True, slots=True)
class CandidateFinding:
    """Candidate finding passed to the validation layer.

    Does NOT carry the full ``State`` — only a narrow snapshot. The agent
    must have enough to reason about the candidate without re-running
    the scan.
    """

    kind: str
    action: Action
    obs: Observation
    state_snapshot: dict[str, Any] = field(default_factory=dict)
    evidence_so_far: dict[str, Any] = field(default_factory=dict)

    def to_prompt_payload(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict to embed into the user message.

        Strips the full page body, caps excerpts at 2000 characters, and
        removes common sensitive keys (cookies, session data, api keys)
        from the state snapshot. Never includes raw auth credentials.
        """
        obs_dict = self.obs.to_dict()
        obs_dict["data"] = _scrub_observation_data(obs_dict.get("data") or {})

        return {
            "kind": self.kind,
            "action": self.action.to_dict(),
            "observation": obs_dict,
            "state_snapshot": _scrub_state_snapshot(dict(self.state_snapshot)),
            "evidence_so_far": dict(self.evidence_so_far),
        }
