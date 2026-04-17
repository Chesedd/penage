from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from penage.core.usage import current_usage_tracker
from penage.llm.base import LLMClient, LLMMessage, LLMResponse


@dataclass(slots=True)
class RoleTaggedLLMClient:
    """Wrapping LLMClient that records usage to the current tracker.

    Satisfies the same duck-typed surface as LLMClient: ``generate()``,
    ``token_usage()`` and ``provider_name``. Usage is attributed to
    ``role`` and, if provided, also to the ``specialist`` map entry in
    the bound :class:`UsageTracker`.

    If no tracker is bound via :func:`bind_usage_tracker`, ``generate``
    still works but does not record anything.
    """

    inner: LLMClient
    role: str
    specialist_name: Optional[str] = None

    @property
    def provider_name(self) -> str:
        return self.inner.provider_name

    def token_usage(self, response: LLMResponse) -> Dict[str, int]:
        return self.inner.token_usage(response)

    async def generate(
        self,
        messages: List[LLMMessage],
        *,
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        resp = await self.inner.generate(
            messages, temperature=temperature, max_tokens=max_tokens
        )
        tracker = current_usage_tracker()
        if tracker is not None:
            try:
                token_usage = self.inner.token_usage(resp)
            except Exception:  # LEGACY: defensive; third-party clients may not provide
                token_usage = {}
            tracker.record_llm_call(
                self.role,
                self.inner.provider_name,
                token_usage,
                specialist=self.specialist_name,
            )
        return resp
