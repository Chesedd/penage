from __future__ import annotations

import json
from dataclasses import dataclass

from penage.agents.base import Agent, AgentRole
from penage.core.usage import UsageTracker
from penage.llm.base import LLMClient, LLMMessage
from penage.prompts.loader import load_prompt
from penage.utils.jsonx import parse_json_object
from penage.validation.candidate import CandidateFinding
from penage.validation.verdict import ValidationVerdict


@dataclass(slots=True)
class ValidationAgent(Agent):
    """MAPTA-style Validation role: confirms or refutes a single candidate.

    Isolated LLM context per call — the agent never carries history
    between candidates. Records LLM usage under the ``"validation"``
    role on the tracker passed per-call.

    Fail-closed contract: any LLM exception or parse error produces a
    ``ValidationVerdict.fail`` with a ``parse_error:`` or
    ``llm_exception:`` reason prefix. The agent never returns ``pass``
    on error.
    """

    @classmethod
    def build(cls, *, llm: LLMClient) -> "ValidationAgent":
        prompt = load_prompt("validation")
        return cls(
            role=AgentRole.VALIDATION,
            system_prompt=prompt,
            llm_client=llm,
        )

    async def validate(
        self,
        candidate: CandidateFinding,
        *,
        tracker: UsageTracker,
    ) -> ValidationVerdict:
        """Run a single LLM call to confirm or refute the candidate."""
        payload = candidate.to_prompt_payload()
        user_message = json.dumps(payload, ensure_ascii=False)
        messages = [
            LLMMessage(role="system", content=self.system_prompt),
            LLMMessage(
                role="user",
                content=f"Candidate finding to validate:\n{user_message}",
            ),
        ]

        try:
            resp = await self.llm_client.generate(messages)
        except Exception as e:
            return ValidationVerdict.fail(f"llm_exception:{type(e).__name__}")

        token_usage = self.llm_client.token_usage(resp)
        tracker.record_llm_call(
            "validation", self.llm_client.provider_name, token_usage,
        )

        parsed = parse_json_object(resp.text)
        if not isinstance(parsed, dict):
            return ValidationVerdict.fail("parse_error:not_a_json_object")

        verdict_str = str(parsed.get("verdict") or "").strip().lower()
        reason = str(parsed.get("reason") or "").strip() or "no_reason_given"
        evidence = parsed.get("evidence") or {}
        if not isinstance(evidence, dict):
            evidence = {}

        if verdict_str == "pass":
            return ValidationVerdict.pass_(reason, **evidence)
        if verdict_str == "fail":
            return ValidationVerdict.fail(reason, **evidence)
        return ValidationVerdict.fail(f"parse_error:unknown_verdict:{verdict_str!r}")
