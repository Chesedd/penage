from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, ClassVar, Dict, List, Optional

from penage.core.errors import LLMResponseError
from penage.llm.base import LLMClient, LLMMessage, LLMResponse
from penage.llm.json_robust import extract_first_json_object, should_force_json

try:
    import openai as _openai
    _OPENAI_AVAILABLE = True
except ImportError:  # pragma: no cover
    _openai = None
    _OPENAI_AVAILABLE = False


DEFAULT_MODEL = "gpt-4o"


@dataclass(slots=True)
class OpenAIClient(LLMClient):

    provider_name: ClassVar[str] = "openai"

    model: str = DEFAULT_MODEL
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    max_output_tokens: Optional[int] = None
    client: Optional[Any] = None

    prefer_json_mode: bool = True

    max_retries: int = 1

    def __post_init__(self) -> None:
        if not _OPENAI_AVAILABLE:
            raise LLMResponseError(
                "openai SDK is not installed; install penage[llm] or pip install openai"
            )

        key = self.api_key or os.environ.get("OPENAI_API_KEY")
        if not key:
            raise LLMResponseError("OPENAI_API_KEY is not set")
        self.api_key = key

    def _get_client(self) -> Any:
        if self.client is None:
            kwargs: Dict[str, Any] = {"api_key": self.api_key}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self.client = _openai.AsyncOpenAI(**kwargs)
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

    def _coerce_turns(self, messages: List[LLMMessage]) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        for m in messages:
            role = m.role if m.role in ("system", "user", "assistant") else "user"
            out.append({"role": role, "content": m.content or ""})
        return out

    async def generate(
        self,
        messages: List[LLMMessage],
        *,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        turns = self._coerce_turns(messages)
        client = self._get_client()

        joined = "\n".join((m.content or "") for m in messages)
        force_json = self.prefer_json_mode and should_force_json(joined)

        kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": turns,
            "temperature": float(temperature),
        }
        tok = max_tokens if max_tokens is not None else self.max_output_tokens
        if tok is not None:
            kwargs["max_tokens"] = int(tok)
        if force_json:
            kwargs["response_format"] = {"type": "json_object"}

        last_err: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = await client.chat.completions.create(**kwargs)
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

        prompt_details = usage.get("prompt_tokens_details") or {}
        if not isinstance(prompt_details, dict):
            prompt_details = {}
        completion_details = usage.get("completion_tokens_details") or {}
        if not isinstance(completion_details, dict):
            completion_details = {}

        return {
            "input_tokens": int(usage.get("prompt_tokens") or 0),
            "output_tokens": int(usage.get("completion_tokens") or 0),
            "cached_tokens": int(prompt_details.get("cached_tokens") or 0),
            "reasoning_tokens": int(completion_details.get("reasoning_tokens") or 0),
        }


def _extract_text(resp: Any) -> str:
    choices = getattr(resp, "choices", None) or []
    if not choices:
        return ""
    first = choices[0]
    msg = getattr(first, "message", None)
    if msg is None:
        return ""
    return str(getattr(msg, "content", "") or "")


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
    if usage_obj is not None:
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            val = getattr(usage_obj, key, None)
            if val is not None:
                usage[key] = val

    return {
        "id": getattr(resp, "id", None),
        "model": getattr(resp, "model", None),
        "usage": usage,
    }
