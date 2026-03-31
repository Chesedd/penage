from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from penage.core.actions import Action
from penage.core.observations import Observation


@dataclass(slots=True)
class TraceEvent:
    ts_ms: int
    event: str
    episode_id: str
    payload: Dict[str, Any]


class JsonlTracer:

    def __init__(self, path: str | Path, *, episode_id: str):
        self.path = Path(path)
        self.episode_id = episode_id
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _now_ms(self) -> int:
        return int(time.time() * 1000)

    def write_event(self, event: str, payload: Dict[str, Any]) -> None:
        rec = TraceEvent(
            ts_ms=self._now_ms(),
            event=event,
            episode_id=self.episode_id,
            payload=payload,
        )
        line = json.dumps(
            {
                "ts_ms": rec.ts_ms,
                "event": rec.event,
                "episode_id": rec.episode_id,
                "payload": rec.payload,
            },
            ensure_ascii=False,
        )
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def record_action(self, action: Action, *, step: int, agent: Optional[str] = None) -> None:
        self.write_event(
            "action",
            {
                "step": step,
                "agent": agent,
                "action": action.to_dict(),
            },
        )

    def record_observation(self, obs: Observation, *, step: int) -> None:
        self.write_event(
            "observation",
            {
                "step": step,
                "observation": obs.to_dict(),
            },
        )

    def record_note(self, text: str, *, step: Optional[int] = None) -> None:
        self.write_event(
            "note",
            {
                "step": step,
                "text": text,
            },
        )

    def record_validation(self, result: Dict[str, Any], *, step: Optional[int] = None) -> None:
        self.write_event(
            "validation",
            {
                "step": step,
                "result": result,
            },
        )

    def record_summary(self, summary: Dict[str, Any], *, step: Optional[int] = None) -> None:
        self.write_event(
            "summary",
            {
                "step": step,
                "summary": summary,
            },
        )

    def record_macro_start(self, name: str, args: Dict[str, Any], *, step: Optional[int] = None) -> None:
        self.write_event(
            "macro_start",
            {
                "step": step,
                "name": name,
                "args": args,
            },
        )

    def record_macro_substep(
        self,
        name: str,
        action: Action,
        obs: Observation,
        *,
        step: Optional[int] = None,
    ) -> None:
        self.write_event(
            "macro_substep",
            {
                "step": step,
                "name": name,
                "action": action.to_dict(),
                "observation": obs.to_dict(),
            },
        )

    def record_macro_result(self, name: str, result: Dict[str, Any], *, step: Optional[int] = None) -> None:
        self.write_event(
            "macro_result",
            {
                "step": step,
                "name": name,
                "result": result,
            },
        )