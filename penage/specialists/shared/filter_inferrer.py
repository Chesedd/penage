from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.state import FilterModel

logger = logging.getLogger(__name__)

_DEFAULT_TAGS: tuple[str, ...] = (
    "<script>",
    "<img>",
    "<svg>",
    "<iframe>",
    "<body>",
    "<div>",
)

_DEFAULT_EVENTS: tuple[str, ...] = (
    "onerror",
    "onload",
    "onmouseover",
    "onfocus",
    "onclick",
)

_DEFAULT_SPECIAL_CHARS: tuple[str, ...] = (
    "<",
    ">",
    '"',
    "'",
    "`",
    "/",
    "\\",
)


@dataclass(frozen=True, slots=True)
class _Probe:
    kind: str  # "tag" | "event" | "char"
    value: str
    payload: str


class _HttpBackend(Protocol):
    async def run(self, action: Action) -> Observation: ...


class FilterInferrer:
    """Infers which tags, events, and special characters a filter lets through.

    Model: byte-exact reflection comparison of each probe payload against the
    response body, using lowercase canonical probe variants (see
    ``_DEFAULT_TAGS`` / ``_DEFAULT_EVENTS``). A probe is labelled ``allowed``
    only when its payload is reflected verbatim between two random markers.

    Known limitation — no case-mix modelling: the inferrer does NOT probe
    case-variant bypasses (``<ScRiPt>``, ``<SCRIPT>``, ``OnErRoR=``, etc.).
    For filters that are case-sensitive (e.g. DVWA XSS medium's naive
    ``str_replace("<script>", "", input)``), the inferrer will mark the
    lowercase tag as blocked even though a case-variant would slip through.
    Prerequisite-gating downstream compensates by preferring ``<img>`` /
    ``<svg>`` tag alternatives over case-mix tricks. Tracked in stage 5
    backlog for high-severity filter classes (DVWA high difficulty).
    """

    def __init__(
        self,
        *,
        tags: tuple[str, ...] = _DEFAULT_TAGS,
        events: tuple[str, ...] = _DEFAULT_EVENTS,
        special_chars: tuple[str, ...] = _DEFAULT_SPECIAL_CHARS,
        timeout_s: float = 10.0,
    ) -> None:
        self._tags = tags
        self._events = events
        self._special_chars = special_chars
        self._timeout_s = float(timeout_s)

    async def infer(
        self,
        base_url: str,
        parameter: str,
        channel: str,
        http_tool: _HttpBackend,
    ) -> FilterModel:
        if not parameter:
            raise ValueError("parameter must be non-empty")
        channel_norm = (channel or "GET").upper()
        if channel_norm not in {"GET", "POST"}:
            raise ValueError(f"unsupported channel: {channel!r}")

        probes = self._build_probes()
        coros = [
            self._probe_once(http_tool, base_url, parameter, channel_norm, probe)
            for probe in probes
        ]
        results = await asyncio.gather(*coros, return_exceptions=True)

        model = FilterModel(parameter=parameter, channel=channel_norm)

        for probe, res in zip(probes, results):
            if isinstance(res, BaseException):
                self._record(model, probe, verdict="blocked")
                continue
            verdict, transform = self._classify(probe, res)
            self._record(model, probe, verdict=verdict, transform=transform)

        return model

    def _build_probes(self) -> list[_Probe]:
        probes: list[_Probe] = []
        for tag in self._tags:
            probes.append(_Probe(kind="tag", value=tag, payload=tag))
        for event in self._events:
            probes.append(_Probe(kind="event", value=event, payload=f"{event}=x"))
        for ch in self._special_chars:
            probes.append(_Probe(kind="char", value=ch, payload=ch))
        return probes

    async def _probe_once(
        self,
        http_tool: _HttpBackend,
        base_url: str,
        parameter: str,
        channel: str,
        probe: _Probe,
    ) -> Observation:
        token = uuid.uuid4().hex[:10]
        marker_a = f"pnaA{token}"
        marker_b = f"pnzB{token}"
        wrapped = f"{marker_a}{probe.payload}{marker_b}"

        if channel == "GET":
            url = _set_query_param(base_url, parameter, wrapped)
            action = Action(
                type=ActionType.HTTP,
                params={"method": "GET", "url": url},
                timeout_s=self._timeout_s,
            )
        else:
            action = Action(
                type=ActionType.HTTP,
                params={
                    "method": "POST",
                    "url": base_url,
                    "data": {parameter: wrapped},
                },
                timeout_s=self._timeout_s,
            )
        obs = await http_tool.run(action)

        if isinstance(obs.data, dict):
            updated = dict(obs.data)
            updated["_marker_a"] = marker_a
            updated["_marker_b"] = marker_b
            return Observation(
                ok=obs.ok,
                data=updated,
                artifacts=list(obs.artifacts),
                elapsed_ms=obs.elapsed_ms,
                error=obs.error,
            )
        return obs

    @staticmethod
    def _classify(probe: _Probe, obs: Observation) -> tuple[str, str | None]:
        if not obs.ok or not isinstance(obs.data, dict):
            return "blocked", None

        text = str(obs.data.get("text_full") or obs.data.get("text_excerpt") or "")
        marker_a = str(obs.data.get("_marker_a") or "")
        marker_b = str(obs.data.get("_marker_b") or "")

        if not marker_a or not marker_b:
            return "blocked", None

        start = text.find(marker_a)
        if start == -1:
            return "blocked", None
        start += len(marker_a)
        end = text.find(marker_b, start)
        if end == -1:
            return "blocked", None

        observed = text[start:end]
        # Byte-exact equality — case-mix variants intentionally treated as blocked.
        # See FilterInferrer class docstring for stage-5 extension plan.
        if observed == probe.payload:
            return "allowed", None
        if observed == "":
            return "blocked", None
        return "transformed", observed

    @staticmethod
    def _record(
        model: FilterModel,
        probe: _Probe,
        *,
        verdict: str,
        transform: str | None = None,
    ) -> None:
        if probe.kind == "tag":
            if verdict == "allowed":
                model.allowed_tags.append(probe.value)
            else:
                model.blocked_tags.append(probe.value)
        elif probe.kind == "event":
            if verdict == "allowed":
                model.allowed_events.append(probe.value)
            else:
                model.blocked_events.append(probe.value)
        elif probe.kind == "char":
            if verdict == "transformed" and transform is not None:
                model.transformed_chars[probe.value] = transform
            elif verdict == "blocked":
                model.transformed_chars.setdefault(probe.value, "")


def _set_query_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    pairs = [(k, v) for (k, v) in pairs if k != name]
    pairs.append((name, value))
    new_query = urlencode(pairs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))
