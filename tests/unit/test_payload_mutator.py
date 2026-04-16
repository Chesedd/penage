from __future__ import annotations

import json
from pathlib import Path

import pytest

from penage.core.state import FilterModel
from penage.llm.base import LLMMessage, LLMResponse
from penage.llm.fake import FakeLLMClient
from penage.specialists.shared.payload_mutator import PayloadMutator
from penage.specialists.shared.reflection_analyzer import (
    ReflectionContext,
    ReflectionContextType,
)


LIBRARY_PATH = Path(__file__).resolve().parents[2] / "penage" / "payloads" / "xss.yaml"


@pytest.mark.asyncio
async def test_mutator_returns_deterministic_payloads_even_without_llm_output():
    llm = FakeLLMClient(fixed_text="")
    mutator = PayloadMutator(llm_client=llm, payload_library_path=LIBRARY_PATH)

    ctx = ReflectionContext(ReflectionContextType.ATTR_QUOTED, quote_char='"', tag_parent="input")
    filter_model = FilterModel(
        parameter="q",
        channel="GET",
        allowed_events=["onfocus"],
    )

    out = await mutator.mutate(ctx, filter_model, max_candidates=3)

    assert out, "expected at least one deterministic payload"
    assert len(out) <= 3
    assert any("onfocus" in p.lower() for p in out)


@pytest.mark.asyncio
async def test_mutator_adds_llm_candidates_after_seeds():
    llm = FakeLLMClient(
        fixed_text=json.dumps(['" autofocus onfocus=confirm(2) x="', "<never>"])
    )
    mutator = PayloadMutator(llm_client=llm, payload_library_path=LIBRARY_PATH)
    ctx = ReflectionContext(ReflectionContextType.ATTR_QUOTED, quote_char='"')
    filter_model = FilterModel(
        parameter="q", channel="GET", allowed_events=["onfocus"]
    )

    out = await mutator.mutate(ctx, filter_model, max_candidates=6)

    assert llm.calls == 1
    assert any("confirm(2)" in p for p in out)
    # Deterministic entries come first
    assert out[0].startswith('"')


@pytest.mark.asyncio
async def test_mutator_falls_back_to_deterministic_on_llm_error():
    class BoomLLM(FakeLLMClient):
        async def generate(self, messages, *, temperature=0.2, max_tokens=None):  # type: ignore[override]
            self.calls += 1
            raise RuntimeError("network down")

    llm = BoomLLM()
    mutator = PayloadMutator(llm_client=llm, payload_library_path=LIBRARY_PATH)
    ctx = ReflectionContext(ReflectionContextType.HTML_BODY)
    filter_model = FilterModel(
        parameter="q",
        channel="GET",
        allowed_tags=["<img>", "<svg>"],
        allowed_events=["onerror", "onload"],
    )

    out = await mutator.mutate(ctx, filter_model, max_candidates=4)

    assert llm.calls == 1
    assert out, "deterministic fallback should still yield payloads"
    assert any("onerror" in p.lower() or "onload" in p.lower() for p in out)


@pytest.mark.asyncio
async def test_mutator_respects_max_candidates_zero():
    llm = FakeLLMClient(fixed_text=json.dumps(["x"]))
    mutator = PayloadMutator(llm_client=llm, payload_library_path=LIBRARY_PATH)
    ctx = ReflectionContext(ReflectionContextType.HTML_BODY)
    filter_model = FilterModel()

    assert await mutator.mutate(ctx, filter_model, max_candidates=0) == []
    assert llm.calls == 0


@pytest.mark.asyncio
async def test_mutator_filters_out_blocked_tag_payloads():
    llm = FakeLLMClient(fixed_text="")
    mutator = PayloadMutator(llm_client=llm, payload_library_path=LIBRARY_PATH)
    ctx = ReflectionContext(ReflectionContextType.HTML_BODY)
    filter_model = FilterModel(
        parameter="q",
        channel="GET",
        allowed_tags=["<img>", "<svg>"],
        allowed_events=["onerror", "onload"],
        blocked_tags=["<script>"],
    )

    out = await mutator.mutate(ctx, filter_model, max_candidates=10)

    assert out, "expected fallback img/svg payloads"
    for payload in out:
        assert "<script" not in payload.lower()


@pytest.mark.asyncio
async def test_mutator_handles_missing_library_gracefully(tmp_path):
    llm = FakeLLMClient(fixed_text=json.dumps(["<img src=x onerror=alert(1)>"]))
    mutator = PayloadMutator(
        llm_client=llm,
        payload_library_path=tmp_path / "missing.yaml",
    )
    ctx = ReflectionContext(ReflectionContextType.HTML_BODY)
    filter_model = FilterModel()

    out = await mutator.mutate(ctx, filter_model, max_candidates=3)

    assert out == ["<img src=x onerror=alert(1)>"]


@pytest.mark.asyncio
async def test_mutator_sends_system_and_user_messages():
    llm = FakeLLMClient(fixed_text="[]")
    mutator = PayloadMutator(llm_client=llm, payload_library_path=LIBRARY_PATH)
    ctx = ReflectionContext(ReflectionContextType.HTML_BODY)
    filter_model = FilterModel()

    await mutator.mutate(ctx, filter_model, max_candidates=2)

    assert llm.last_messages is not None
    roles = [m.role for m in llm.last_messages]
    assert roles == ["system", "user"]
    assert "payloads" in llm.last_messages[0].content.lower()
