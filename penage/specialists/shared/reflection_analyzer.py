from __future__ import annotations

import asyncio
import logging
import re
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation

logger = logging.getLogger(__name__)

_CANARY_COUNT = 8
_CANARY_PREFIX = "pncy"
_CONTEXT_WINDOW = 160
_TAG_NAME_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9\-]*)")
_SCRIPT_OPEN_RE = re.compile(r"<script\b[^>]*>", re.IGNORECASE)
_SCRIPT_CLOSE_RE = re.compile(r"</script\s*>", re.IGNORECASE)


class ReflectionContextType(str, Enum):
    HTML_BODY = "html_body"
    ATTR_QUOTED = "attr_quoted"
    ATTR_UNQUOTED = "attr_unquoted"
    JS_STRING = "js_string"
    SCRIPT_BLOCK = "script_block"
    JSON_VALUE = "json_value"
    URL_REDIRECT = "url_redirect"
    NOT_REFLECTED = "not_reflected"


@dataclass(frozen=True, slots=True)
class ReflectionContext:
    context_type: ReflectionContextType
    quote_char: str | None = None
    tag_parent: str | None = None
    encoding_observed: str | None = None


@dataclass(slots=True)
class ReflectionResult:
    parameter: str
    contexts: list[ReflectionContext] = field(default_factory=list)
    channels: list[str] = field(default_factory=list)
    raw_responses: dict[str, Any] = field(default_factory=dict)


class _HttpBackend(Protocol):
    async def run(self, action: Action) -> Observation: ...


class ReflectionAnalyzer:
    """Parallel canary injection + DOM-context classification.

    Sends canaries across GET and POST channels using the provided HTTP tool
    (implements :class:`penage.tools.http_backend.HttpBackend`), then classifies
    the lexical context each reflected canary lands in.
    """

    def __init__(self, *, canary_count: int = _CANARY_COUNT, timeout_s: float = 10.0) -> None:
        self._canary_count = max(2, int(canary_count))
        self._timeout_s = float(timeout_s)

    async def analyze(
        self,
        base_url: str,
        parameter: str,
        http_tool: _HttpBackend,
    ) -> ReflectionResult:
        if not parameter:
            raise ValueError("parameter must be non-empty")

        canaries = [self._make_canary(i) for i in range(self._canary_count)]
        half = self._canary_count // 2
        channels = ["GET"] * half + ["POST"] * (self._canary_count - half)

        coros = [
            self._send(http_tool, base_url, parameter, canary, channel)
            for canary, channel in zip(canaries, channels)
        ]
        observations = await asyncio.gather(*coros, return_exceptions=True)

        contexts: list[ReflectionContext] = []
        channels_with_reflection: set[str] = set()
        raw: dict[str, Any] = {}

        for canary, channel, obs in zip(canaries, channels, observations):
            if isinstance(obs, BaseException):
                raw[canary] = {"channel": channel, "error": repr(obs)}
                continue

            raw[canary] = {
                "channel": channel,
                "status": obs.data.get("status_code") if obs.ok else None,
                "url": obs.data.get("url") if obs.ok else None,
                "text_len": len(str(obs.data.get("text_full") or "")) if obs.ok else 0,
            }

            ctx = self._classify_response(canary, obs)
            if ctx is None or ctx.context_type == ReflectionContextType.NOT_REFLECTED:
                continue
            contexts.append(ctx)
            channels_with_reflection.add(channel)

        if not contexts:
            contexts.append(ReflectionContext(ReflectionContextType.NOT_REFLECTED))

        return ReflectionResult(
            parameter=parameter,
            contexts=self._dedupe(contexts),
            channels=sorted(channels_with_reflection),
            raw_responses=raw,
        )

    @staticmethod
    def _make_canary(index: int) -> str:
        return f"{_CANARY_PREFIX}{index}{uuid.uuid4().hex[:10]}"

    async def _send(
        self,
        http_tool: _HttpBackend,
        base_url: str,
        parameter: str,
        canary: str,
        channel: str,
    ) -> Observation:
        if channel == "GET":
            url = _set_query_param(base_url, parameter, canary)
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
                    "data": {parameter: canary},
                },
                timeout_s=self._timeout_s,
            )
        return await http_tool.run(action)

    def _classify_response(self, canary: str, obs: Observation) -> ReflectionContext | None:
        if not obs.ok:
            return None
        data = obs.data or {}
        text = str(data.get("text_full") or data.get("text_excerpt") or "")
        headers = data.get("headers") or {}
        content_type = str(headers.get("content-type") or headers.get("Content-Type") or "").lower()
        location = str(headers.get("location") or headers.get("Location") or "")
        status = data.get("status_code")

        if canary in location and isinstance(status, int) and 300 <= status < 400:
            return ReflectionContext(
                ReflectionContextType.URL_REDIRECT,
                encoding_observed=_detect_encoding(canary, location),
            )

        if canary not in text:
            return ReflectionContext(ReflectionContextType.NOT_REFLECTED)

        encoding = _detect_encoding(canary, text)

        if "application/json" in content_type and not _looks_like_html(text):
            return ReflectionContext(
                ReflectionContextType.JSON_VALUE,
                encoding_observed=encoding,
            )

        return _classify_html_context(text, canary, encoding)

    @staticmethod
    def _dedupe(contexts: list[ReflectionContext]) -> list[ReflectionContext]:
        seen: set[tuple[Any, ...]] = set()
        out: list[ReflectionContext] = []
        for c in contexts:
            key = (c.context_type, c.quote_char, c.tag_parent, c.encoding_observed)
            if key in seen:
                continue
            seen.add(key)
            out.append(c)
        return out


def _set_query_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    pairs = [(k, v) for (k, v) in pairs if k != name]
    pairs.append((name, value))
    new_query = urlencode(pairs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _looks_like_html(text: str) -> bool:
    low = text.lower()
    return "<html" in low or "<body" in low or "<script" in low or "<div" in low


def _detect_encoding(canary: str, text: str) -> str | None:
    if canary in text:
        return None
    url_encoded = canary.replace("-", "%2D")
    if url_encoded != canary and url_encoded in text:
        return "url_encoded"
    return None


def _classify_html_context(text: str, canary: str, encoding: str | None) -> ReflectionContext:
    idx = text.find(canary)
    if idx == -1:
        return ReflectionContext(ReflectionContextType.NOT_REFLECTED, encoding_observed=encoding)

    start = max(0, idx - _CONTEXT_WINDOW)
    before = text[start:idx]

    last_script_open = _last_match_end(_SCRIPT_OPEN_RE, before)
    last_script_close = _last_match_end(_SCRIPT_CLOSE_RE, before)

    if last_script_open is not None and (last_script_close is None or last_script_open > last_script_close):
        script_prefix = before[last_script_open:]
        quote = _unpaired_quote(script_prefix)
        if quote is not None:
            return ReflectionContext(
                ReflectionContextType.JS_STRING,
                quote_char=quote,
                tag_parent="script",
                encoding_observed=encoding,
            )
        return ReflectionContext(
            ReflectionContextType.SCRIPT_BLOCK,
            tag_parent="script",
            encoding_observed=encoding,
        )

    last_lt = before.rfind("<")
    last_gt = before.rfind(">")

    if last_lt > last_gt:
        tag_portion = before[last_lt:]
        tag_match = _TAG_NAME_RE.match(tag_portion)
        tag_parent = tag_match.group(1).lower() if tag_match else None
        last_eq = tag_portion.rfind("=")
        if last_eq != -1:
            after_eq = tag_portion[last_eq + 1 :].lstrip()
            if after_eq.startswith('"'):
                return ReflectionContext(
                    ReflectionContextType.ATTR_QUOTED,
                    quote_char='"',
                    tag_parent=tag_parent,
                    encoding_observed=encoding,
                )
            if after_eq.startswith("'"):
                return ReflectionContext(
                    ReflectionContextType.ATTR_QUOTED,
                    quote_char="'",
                    tag_parent=tag_parent,
                    encoding_observed=encoding,
                )
            return ReflectionContext(
                ReflectionContextType.ATTR_UNQUOTED,
                tag_parent=tag_parent,
                encoding_observed=encoding,
            )
        return ReflectionContext(
            ReflectionContextType.ATTR_UNQUOTED,
            tag_parent=tag_parent,
            encoding_observed=encoding,
        )

    return ReflectionContext(ReflectionContextType.HTML_BODY, encoding_observed=encoding)


def _last_match_end(pattern: re.Pattern[str], text: str) -> int | None:
    last_end = None
    for m in pattern.finditer(text):
        last_end = m.end()
    return last_end


def _unpaired_quote(segment: str) -> str | None:
    """Return the unpaired quote character opened before canary, or None."""
    stack: list[str] = []
    i = 0
    while i < len(segment):
        ch = segment[i]
        if ch == "\\":
            i += 2
            continue
        if ch in ('"', "'", "`"):
            if stack and stack[-1] == ch:
                stack.pop()
            elif not stack:
                stack.append(ch)
        i += 1
    return stack[-1] if stack else None
