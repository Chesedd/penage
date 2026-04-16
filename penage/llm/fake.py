from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Dict, List, Optional

from penage.llm.base import LLMClient, LLMMessage, LLMResponse


@dataclass(slots=True)
class FakeLLMClient(LLMClient):
    provider_name: ClassVar[str] = "fake"

    fixed_text: Optional[str] = None
    scripted: Optional[List[str]] = None
    calls: int = 0
    last_messages: Optional[List[LLMMessage]] = None

    async def generate(
        self,
        messages: List[LLMMessage],
        *,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        self.calls += 1
        self.last_messages = messages
        if self.scripted:
            idx = min(self.calls - 1, len(self.scripted) - 1)
            return LLMResponse(text=self.scripted[idx], raw={"messages": messages})
        return LLMResponse(text=self.fixed_text or "", raw={"messages": messages})

    def token_usage(self, response: LLMResponse) -> Dict[str, int]:
        return {"input_tokens": 0, "output_tokens": 0, "cached_tokens": 0, "reasoning_tokens": 0}