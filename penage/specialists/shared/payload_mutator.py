from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from penage.core.state import FilterModel
from penage.llm.base import LLMClient, LLMMessage
from penage.specialists.shared.reflection_analyzer import (
    ReflectionContext,
    ReflectionContextType,
)

logger = logging.getLogger(__name__)

_EVENT_RE = re.compile(r"\bon[a-z]+\b")


@dataclass(frozen=True, slots=True)
class _LibraryEntry:
    id: str
    context: str
    prerequisites: dict[str, Any] = field(default_factory=dict)
    template: str = ""
    description: str = ""


class PayloadMutator:
    """Hybrid payload generator: deterministic YAML library + LLM mutations.

    Loading happens lazily so a missing file does not break import. On any LLM
    error (exception, empty response, unparseable output) ``mutate`` falls back
    to the deterministic selection only.
    """

    def __init__(self, llm_client: LLMClient, payload_library_path: Path) -> None:
        self._llm = llm_client
        self._library_path = Path(payload_library_path)
        self._library: list[_LibraryEntry] | None = None

    async def mutate(
        self,
        context: ReflectionContext,
        filter_model: FilterModel,
        max_candidates: int = 5,
    ) -> list[str]:
        if max_candidates <= 0:
            return []

        entries = self._select_entries(context, filter_model)
        deterministic = [e.template for e in entries if e.template]

        try:
            llm_candidates = await self._generate_llm_mutations(
                context=context,
                filter_model=filter_model,
                seeds=deterministic,
                max_candidates=max_candidates,
            )
        except Exception as exc:  # LEGACY: any LLM-layer failure -> deterministic fallback
            logger.warning("payload mutator LLM call failed: %s; using deterministic only", exc)
            llm_candidates = []

        combined: list[str] = []
        seen: set[str] = set()
        for payload in list(deterministic) + list(llm_candidates):
            p = (payload or "").strip()
            if not p or p in seen:
                continue
            seen.add(p)
            combined.append(p)
            if len(combined) >= max_candidates:
                break
        return combined

    def _load_library(self) -> list[_LibraryEntry]:
        if self._library is not None:
            return self._library
        try:
            import yaml  # noqa: WPS433 — local import so yaml stays soft-optional for tests
        except ImportError as exc:
            logger.warning("PyYAML not installed (%s); payload library unavailable", exc)
            self._library = []
            return self._library

        if not self._library_path.exists():
            logger.warning("payload library missing at %s", self._library_path)
            self._library = []
            return self._library

        try:
            raw = yaml.safe_load(self._library_path.read_text(encoding="utf-8")) or []
        except Exception as exc:
            logger.warning("failed to parse payload library %s: %s", self._library_path, exc)
            self._library = []
            return self._library

        entries: list[_LibraryEntry] = []
        if not isinstance(raw, list):
            self._library = []
            return self._library
        for item in raw:
            if not isinstance(item, dict):
                continue
            entries.append(
                _LibraryEntry(
                    id=str(item.get("id") or ""),
                    context=str(item.get("context") or ""),
                    prerequisites=dict(item.get("prerequisites") or {}),
                    template=str(item.get("template") or ""),
                    description=str(item.get("description") or ""),
                )
            )
        self._library = entries
        return entries

    def _select_entries(
        self,
        context: ReflectionContext,
        filter_model: FilterModel,
    ) -> list[_LibraryEntry]:
        library = self._load_library()
        if not library:
            return []
        target_context = context.context_type.value
        allowed_tags = {_strip_tag(t) for t in filter_model.allowed_tags}
        allowed_events = {e.lower() for e in filter_model.allowed_events}
        blocked_tags = {_strip_tag(t) for t in filter_model.blocked_tags}
        blocked_events = {e.lower() for e in filter_model.blocked_events}

        survivors: list[_LibraryEntry] = []
        for entry in library:
            if entry.context and entry.context != target_context:
                continue
            if not _prereqs_satisfied(
                entry.prerequisites,
                allowed_tags=allowed_tags,
                allowed_events=allowed_events,
            ):
                continue
            if _payload_uses_blocked(entry.template, blocked_tags, blocked_events):
                continue
            survivors.append(entry)
        return survivors

    async def mutate_by_category(
        self,
        category: str,
        filter_model: FilterModel,
        *,
        backend: str | None = None,
        max_candidates: int = 5,
    ) -> list[str]:
        """Variant of :meth:`mutate` keyed by a free-form category string.

        Intended for non-XSS specialists (SQLi, SSTI, …). Filters library
        entries by ``entry.context == category`` and (optionally) by
        ``prerequisites.backend``. LLM failures degrade to deterministic
        candidates only, preserving the same never-crashes contract.
        """
        if max_candidates <= 0 or not category:
            return []

        library = self._load_library()
        survivors: list[_LibraryEntry] = []
        for entry in library:
            if entry.context != category:
                continue
            wanted_backend = entry.prerequisites.get("backend")
            if backend is not None and wanted_backend and str(wanted_backend).lower() != backend.lower():
                continue
            survivors.append(entry)

        deterministic = [e.template for e in survivors if e.template]

        try:
            llm_candidates = await self._generate_category_mutations(
                category=category,
                backend=backend,
                filter_model=filter_model,
                seeds=deterministic,
                max_candidates=max_candidates,
            )
        except Exception as exc:  # LEGACY: LLM failures never bubble up
            logger.warning(
                "payload mutator LLM call (category=%s) failed: %s; using deterministic only",
                category,
                exc,
            )
            llm_candidates = []

        combined: list[str] = []
        seen: set[str] = set()
        for payload in list(deterministic) + list(llm_candidates):
            p = (payload or "").strip()
            if not p or p in seen:
                continue
            seen.add(p)
            combined.append(p)
            if len(combined) >= max_candidates:
                break
        return combined

    async def _generate_category_mutations(
        self,
        *,
        category: str,
        backend: str | None,
        filter_model: FilterModel,
        seeds: list[str],
        max_candidates: int,
    ) -> list[str]:
        system = (
            "You mutate injection payloads for authorized security testing. "
            "Return a JSON array of strings only. No prose, no markdown fences."
        )
        user = json.dumps(
            {
                "category": category,
                "backend": backend,
                "filter_model": {
                    "allowed_tags": list(filter_model.allowed_tags),
                    "blocked_tags": list(filter_model.blocked_tags),
                    "transformed_chars": dict(filter_model.transformed_chars),
                },
                "seed_payloads": seeds[:6],
                "max_candidates": max_candidates,
                "instruction": (
                    "Return up to max_candidates distinct payload strings as a JSON array. "
                    "Stay within the category and (when given) backend. No commentary."
                ),
            }
        )
        response = await self._llm.generate(
            [
                LLMMessage(role="system", content=system),
                LLMMessage(role="user", content=user),
            ],
            temperature=0.3,
        )
        text = (response.text or "").strip()
        if not text:
            return []
        return _parse_json_string_list(text)[:max_candidates]

    async def _generate_llm_mutations(
        self,
        *,
        context: ReflectionContext,
        filter_model: FilterModel,
        seeds: list[str],
        max_candidates: int,
    ) -> list[str]:
        system = (
            "You mutate XSS payloads for authorized security testing. "
            "Return a JSON array of strings only. No prose, no markdown fences. "
            "Honor the filter constraints exactly."
        )
        user = json.dumps(
            {
                "context": {
                    "type": context.context_type.value,
                    "quote_char": context.quote_char,
                    "tag_parent": context.tag_parent,
                    "encoding_observed": context.encoding_observed,
                },
                "filter_model": {
                    "allowed_tags": list(filter_model.allowed_tags),
                    "blocked_tags": list(filter_model.blocked_tags),
                    "allowed_events": list(filter_model.allowed_events),
                    "blocked_events": list(filter_model.blocked_events),
                    "transformed_chars": dict(filter_model.transformed_chars),
                },
                "seed_payloads": seeds[:6],
                "max_candidates": max_candidates,
                "instruction": (
                    "Return up to max_candidates distinct payload strings as a JSON array. "
                    "Each payload must avoid blocked tags/events/chars."
                ),
            }
        )

        response = await self._llm.generate(
            [
                LLMMessage(role="system", content=system),
                LLMMessage(role="user", content=user),
            ],
            temperature=0.3,
        )
        text = (response.text or "").strip()
        if not text:
            return []
        return _parse_json_string_list(text)[:max_candidates]


def _strip_tag(tag: str) -> str:
    t = tag.strip().lower()
    if t.startswith("<"):
        t = t[1:]
    if t.endswith(">"):
        t = t[:-1]
    return t.split()[0] if t else ""


def _prereqs_satisfied(
    prereqs: dict[str, Any],
    *,
    allowed_tags: set[str],
    allowed_events: set[str],
) -> bool:
    needed_tags = prereqs.get("tags") or []
    needed_events = prereqs.get("events") or []
    if needed_tags and allowed_tags:
        need = {_strip_tag(str(t)) for t in needed_tags}
        if not need.issubset(allowed_tags):
            return False
    if needed_events and allowed_events:
        need = {str(e).lower() for e in needed_events}
        if not need.issubset(allowed_events):
            return False
    return True


def _payload_uses_blocked(
    template: str,
    blocked_tags: set[str],
    blocked_events: set[str],
) -> bool:
    if not template:
        return False
    low = template.lower()
    for tag in blocked_tags:
        if tag and f"<{tag}" in low:
            return True
    for event in _EVENT_RE.findall(low):
        if event in blocked_events:
            return True
    return False


def _parse_json_string_list(text: str) -> list[str]:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        stripped = "\n".join(ln for ln in lines if not ln.strip().startswith("```"))
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(p) for p in parsed if isinstance(p, (str, int, float)) and str(p).strip()]
