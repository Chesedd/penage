from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol


@dataclass(frozen=True, slots=True)
class LLMMessage:
    role: str  # "system" | "user" | "assistant"
    content: str


@dataclass(frozen=True, slots=True)
class LLMResponse:
    text: str
    usage: Optional[Dict[str, Any]] = None
    raw: Optional[Any] = None


class LLMClient(Protocol):
    provider_name: str

    async def generate(
        self,
        messages: List[LLMMessage],
        *,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse: ...

    def token_usage(self, response: LLMResponse) -> Dict[str, int]:
        """Return {input_tokens, output_tokens, cached_tokens, reasoning_tokens}.

        Unsupported fields return 0 rather than being omitted.
        """
        ...
