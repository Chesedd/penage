from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, ClassVar, Dict, List, Optional

from penage.core.errors import LLMResponseError
from penage.llm.base import LLMClient, LLMMessage, LLMResponse
from penage.llm.json_robust import extract_first_json_object, should_force_json

try:
    import anthropic as _anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:  # pragma: no cover
    _anthropic = None
    _ANTHROPIC_AVAILABLE = False


DEFAULT_MODEL = "claude-sonnet-4-20250514"


@dataclass(slots=True)
class AnthropicClient(LLMClient):

    provider_name: ClassVar[str] = "anthropic"

    model: str = DEFAULT_MODEL
    api_key: Optional[str] = None
    max_output_tokens: int = 4096
    client: Optional[Any] = None

    prefer_json_mode: bool = True

    max_retries: int = 1

    def __post_init__(self) -> None:
        if not _ANTHROPIC_AVAILABLE:
            raise LLMResponseError(
                "anthropic SDK is not installed; install penage[llm] or pip install anthropic"
            )

        key = self.api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise LLMResponseError("ANTHROPIC_API_KEY is not set")
        self.api_key = key

    def _get_client(self) -> Any:
        if self.client is None:
            self.client = _anthropic.AsyncAnthropic(api_key=self.api_key)
        return self.client

    async def aclose(self) -> None:
        client = self.client
        if client is None:
            return
        aclose = getattr(client, "aclose", None) or getattr(client, "close", None)
        if aclose is None:
            return
        result = aclose()
        if hasattr(result, "__await__"):
            await result

    def _split_system_and_turns(
        self, messages: List[LLMMessage]
    ) -> tuple[str, List[Dict[str, str]]]:
        system_parts: List[str] = []
        turns: List[Dict[str, str]] = []
        for m in messages:
            if m.role == "system":
                system_parts.append(m.content or "")
                continue
            role = m.role if m.role in ("user", "assistant") else "user"
            turns.append({"role": role, "content": m.content or ""})
        system = "\n\n".join(p for p in system_parts if p)
        return system, turns

    async def generate(
        self,
        messages: List[LLMMessage],
        *,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        system, turns = self._split_system_and_turns(messages)
        client = self._get_client()

        joined = "\n".join((m.content or "") for m in messages)
        force_json = self.prefer_json_mode and should_force_json(joined)

        kwargs: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": int(max_tokens if max_tokens is not None else self.max_output_tokens),
            "messages": turns,
            "temperature": float(temperature),
        }
        if system:
            kwargs["system"] = system

        last_err: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = await client.messages.create(**kwargs)
            except Exception as e:  # LEGACY: SDK raises its own hierarchy; wrap at boundary
                last_err = e
                if attempt >= self.max_retries:
                    stop_plan = {
                        "stop": True,
                        "stop_reason": f"llm_error:{type(e).__name__}",
                        "actions": [],
                    }
                    return LLMResponse(text=json.dumps(stop_plan), raw={"error": str(e)})
                continue

            text = _extract_text(resp)
            raw = _response_to_dict(resp)

            if not force_json:
                return LLMResponse(text=text, raw=raw)

            parsed = extract_first_json_object(text)
            if parsed is not None or attempt >= self.max_retries:
                return LLMResponse(text=text, raw=raw)

            kwargs["messages"] = kwargs["messages"] + [
                {
                    "role": "user",
                    "content": "Your previous response was not valid JSON. Return ONLY a valid JSON object.",
                }
            ]

        stop_plan = {
            "stop": True,
            "stop_reason": f"llm_error:{type(last_err).__name__ if last_err else 'unknown'}",
            "actions": [],
        }
        return LLMResponse(text=json.dumps(stop_plan), raw={"error": str(last_err) if last_err else "unknown"})

    def token_usage(self, response: LLMResponse) -> Dict[str, int]:
        raw = response.raw if isinstance(response.raw, dict) else {}
        usage = raw.get("usage") if isinstance(raw.get("usage"), dict) else {}

        cache_read = int(usage.get("cache_read_input_tokens") or 0)
        cache_create = int(usage.get("cache_creation_input_tokens") or 0)

        return {
            "input_tokens": int(usage.get("input_tokens") or 0),
            "output_tokens": int(usage.get("output_tokens") or 0),
            "cached_tokens": cache_read + cache_create,
            "reasoning_tokens": 0,
        }


def _extract_text(resp: Any) -> str:
    content = getattr(resp, "content", None) or []
    parts: List[str] = []
    for block in content:
        btype = getattr(block, "type", None)
        if btype == "text":
            parts.append(str(getattr(block, "text", "") or ""))
    return "".join(parts)


def _response_to_dict(resp: Any) -> Dict[str, Any]:
    model_dump = getattr(resp, "model_dump", None)
    if callable(model_dump):
        try:
            d = model_dump()
            if isinstance(d, dict):
                return d
        except (TypeError, ValueError):
            pass

    usage_obj = getattr(resp, "usage", None)
    usage: Dict[str, Any] = {}
    for key in ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens"):
        val = getattr(usage_obj, key, None)
        if val is not None:
            usage[key] = val

    return {
        "id": getattr(resp, "id", None),
        "model": getattr(resp, "model", None),
        "usage": usage,
    }
