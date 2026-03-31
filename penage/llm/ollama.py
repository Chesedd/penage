from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from penage.llm.base import LLMClient, LLMMessage, LLMResponse

_JSON_FENCE_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)

_JSON_HINTS = (
    "return only json",
    "return only a json object",
    "return json",
    "output schema",
    "\"actions\"",
    "'actions'",
    "valid json object",
)


def extract_first_json_object(text: str) -> Optional[Dict[str, Any]]:
    m = _JSON_FENCE_RE.search(text)
    if m:
        candidate = m.group(1)
        try:
            return json.loads(candidate)
        except Exception:
            return None

    if "{" in text and "}" in text:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            candidate = text[start : end + 1]
            try:
                return json.loads(candidate)
            except Exception:
                return None
    return None


def _clip_middle(text: str, limit: int) -> str:
    if limit <= 0 or len(text) <= limit:
        return text
    keep_head = max(1, int(limit * 0.65))
    keep_tail = max(1, limit - keep_head)
    return text[:keep_head] + "\n<...clipped...>\n" + text[-keep_tail:]


@dataclass(slots=True)
class OllamaClient(LLMClient):

    model: str
    base_url: str = "http://localhost:11434"
    client: Optional[httpx.AsyncClient] = None

    request_timeout_s: float = 120.0
    connect_timeout_s: float = 10.0
    write_timeout_s: float = 30.0
    pool_timeout_s: float = 30.0

    max_retries: int = 1

    # Robustness knobs for local models
    prefer_json_mode: bool = True
    max_message_chars: int = 60_000
    max_total_chars: int = 110_000

    # Useful Ollama generation defaults for planner loops
    default_num_ctx: int = 65536
    default_num_predict: int = 1200

    def _get_client(self) -> httpx.AsyncClient:
        if self.client is None:
            timeout = httpx.Timeout(
                connect=self.connect_timeout_s,
                read=self.request_timeout_s,
                write=self.write_timeout_s,
                pool=self.pool_timeout_s,
            )
            self.client = httpx.AsyncClient(base_url=self.base_url, timeout=timeout)
        return self.client

    async def aclose(self) -> None:
        if self.client:
            await self.client.aclose()

    def _should_force_json(self, messages: List[LLMMessage]) -> bool:
        if not self.prefer_json_mode:
            return False

        joined = "\n".join((m.content or "") for m in messages).lower()
        return any(h in joined for h in _JSON_HINTS)

    def _budget_messages(self, messages: List[LLMMessage]) -> List[LLMMessage]:
        """
        Keep message list structure intact, but compact very large user/system contents.
        We preserve the newest messages and aggressively clip oversized content blocks.
        """
        if not messages:
            return messages

        compacted: List[LLMMessage] = []
        for m in messages:
            content = m.content or ""
            if len(content) > self.max_message_chars:
                content = _clip_middle(content, self.max_message_chars)
            compacted.append(LLMMessage(role=m.role, content=content))

        total = sum(len(m.content or "") for m in compacted)
        if total <= self.max_total_chars:
            return compacted

        # First, compact non-system messages harder from oldest to newest.
        tmp = compacted[:]
        overflow = total - self.max_total_chars
        for idx, m in enumerate(tmp):
            if overflow <= 0:
                break
            if m.role == "system":
                continue

            content = m.content or ""
            if len(content) < 4000:
                continue

            new_limit = max(3000, len(content) - overflow)
            new_content = _clip_middle(content, new_limit)
            overflow -= max(0, len(content) - len(new_content))
            tmp[idx] = LLMMessage(role=m.role, content=new_content)

        total2 = sum(len(m.content or "") for m in tmp)
        if total2 <= self.max_total_chars:
            return tmp

        # Last-resort compaction for all messages except keep some system prompt.
        overflow = total2 - self.max_total_chars
        out: List[LLMMessage] = []
        for m in tmp:
            content = m.content or ""
            if overflow > 0:
                floor = 2500 if m.role != "system" else 4000
                if len(content) > floor:
                    new_limit = max(floor, len(content) - overflow)
                    new_content = _clip_middle(content, new_limit)
                    overflow -= max(0, len(content) - len(new_content))
                    content = new_content
            out.append(LLMMessage(role=m.role, content=content))
        return out

    def _build_payload(
        self,
        messages: List[LLMMessage],
        temperature: float,
        max_tokens: Optional[int],
    ) -> Dict[str, Any]:
        use_messages = self._budget_messages(messages)

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in use_messages],
            "options": {
                "temperature": temperature,
                "num_ctx": self.default_num_ctx,
                "num_predict": max_tokens if max_tokens is not None else self.default_num_predict,
            },
            "stream": False,
        }

        if self._should_force_json(use_messages):
            payload["format"] = "json"

        return payload

    async def _post_chat(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        client = self._get_client()
        resp = await client.post("/api/chat", json=payload)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise httpx.RemoteProtocolError("Ollama /api/chat returned non-object JSON")
        return data

    def _response_text(self, data: Dict[str, Any]) -> str:
        return str(((data.get("message") or {}).get("content")) or "")

    def _response_usage(self, data: Dict[str, Any]) -> Dict[str, Any]:
        usage: Dict[str, Any] = {}
        for key in (
            "total_duration",
            "load_duration",
            "prompt_eval_count",
            "prompt_eval_duration",
            "eval_count",
            "eval_duration",
        ):
            if key in data:
                usage[key] = data.get(key)
        return usage

    async def generate(
            self,
            messages: List[LLMMessage],
            *,
            temperature: float = 0.2,
            max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        payload = self._build_payload(messages, temperature, max_tokens)
        client = self._get_client()

        last_text = ""
        last_raw: Optional[dict] = None
        last_err: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            try:
                resp = await client.post("/api/chat", json=payload)
                resp.raise_for_status()
                data = resp.json()
                last_raw = data

                text = ((data.get("message") or {}).get("content")) or ""
                last_text = text

                parsed = extract_first_json_object(text)
                if parsed is not None or attempt >= self.max_retries:
                    return LLMResponse(text=text, raw=data)

                payload["messages"] = payload["messages"] + [
                    {
                        "role": "user",
                        "content": "Your previous response was not valid JSON. Return ONLY a valid JSON object.",
                    }
                ]

            except httpx.HTTPStatusError as e:
                last_err = e
                status = e.response.status_code if e.response is not None else "unknown"
                body = ""
                try:
                    body = (e.response.text or "")[:800] if e.response is not None else ""
                except Exception:
                    body = ""

                if attempt >= self.max_retries:
                    stop_plan = {
                        "stop": True,
                        "stop_reason": f"llm_http_error:{status}",
                        "actions": [],
                    }
                    return LLMResponse(
                        text=json.dumps(stop_plan),
                        raw={
                            "error": str(e),
                            "status_code": status,
                            "response_excerpt": body,
                        },
                    )

            except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.PoolTimeout, httpx.RemoteProtocolError,
                    httpx.TransportError) as e:
                last_err = e
                if attempt >= self.max_retries:
                    stop_plan = {
                        "stop": True,
                        "stop_reason": f"llm_timeout_or_transport_error:{type(e).__name__}",
                        "actions": [],
                    }
                    return LLMResponse(text=json.dumps(stop_plan), raw={"error": str(e)})

        if last_err is not None:
            stop_plan = {
                "stop": True,
                "stop_reason": f"llm_error:{type(last_err).__name__}",
                "actions": [],
            }
            return LLMResponse(text=json.dumps(stop_plan), raw={"error": str(last_err)})

        return LLMResponse(
            text=json.dumps({"stop": True, "stop_reason": "llm_unknown_error", "actions": []}),
            raw={"error": "unknown"},
        )