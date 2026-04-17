"""Unit tests for the env-driven E2E config helper."""
from __future__ import annotations

import pytest

from tests.support.e2e_config import (
    LlmChoice,
    detect_llm_choice,
    detect_sandbox_backend,
)


class TestDetectLlmChoice:
    def test_explicit_provider_with_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PENAGE_E2E_LLM_PROVIDER", "openai")
        monkeypatch.setenv("PENAGE_E2E_LLM_MODEL", "gpt-4o-mini")
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        assert detect_llm_choice() == LlmChoice(provider="openai", model="gpt-4o-mini")

    def test_explicit_provider_default_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PENAGE_E2E_LLM_PROVIDER", "openai")
        monkeypatch.delenv("PENAGE_E2E_LLM_MODEL", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        choice = detect_llm_choice()
        assert choice is not None
        assert choice.provider == "openai"
        assert choice.model  # DEFAULT_MODEL from penage.llm.openai

    def test_explicit_anthropic_default_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PENAGE_E2E_LLM_PROVIDER", "anthropic")
        monkeypatch.delenv("PENAGE_E2E_LLM_MODEL", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        choice = detect_llm_choice()
        assert choice is not None
        assert choice.provider == "anthropic"
        assert choice.model

    def test_explicit_ollama_requires_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PENAGE_E2E_LLM_PROVIDER", "ollama")
        monkeypatch.delenv("PENAGE_E2E_LLM_MODEL", raising=False)
        choice = detect_llm_choice()
        assert choice is not None
        assert choice.provider == "ollama"
        assert choice.model == ""  # builder will pytest.skip on this

    def test_explicit_unknown_provider_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PENAGE_E2E_LLM_PROVIDER", "bogus")
        with pytest.raises(ValueError, match="openai/anthropic/ollama"):
            detect_llm_choice()

    def test_autodetect_openai_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PENAGE_E2E_LLM_PROVIDER", raising=False)
        monkeypatch.delenv("PENAGE_E2E_LLM_MODEL", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        choice = detect_llm_choice()
        assert choice is not None
        assert choice.provider == "openai"
        assert choice.model

    def test_autodetect_anthropic_key_when_no_openai(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PENAGE_E2E_LLM_PROVIDER", raising=False)
        monkeypatch.delenv("PENAGE_E2E_LLM_MODEL", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        choice = detect_llm_choice()
        assert choice is not None
        assert choice.provider == "anthropic"

    def test_openai_takes_priority_over_anthropic(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PENAGE_E2E_LLM_PROVIDER", raising=False)
        monkeypatch.delenv("PENAGE_E2E_LLM_MODEL", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
        choice = detect_llm_choice()
        assert choice is not None
        assert choice.provider == "openai"

    def test_model_override_applies_to_autodetect(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PENAGE_E2E_LLM_PROVIDER", raising=False)
        monkeypatch.setenv("PENAGE_E2E_LLM_MODEL", "gpt-4o-mini")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        choice = detect_llm_choice()
        assert choice is not None
        assert choice == LlmChoice(provider="openai", model="gpt-4o-mini")

    def test_no_keys_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PENAGE_E2E_LLM_PROVIDER", raising=False)
        monkeypatch.delenv("PENAGE_E2E_LLM_MODEL", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        assert detect_llm_choice() is None

    def test_provider_casing_is_normalized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PENAGE_E2E_LLM_PROVIDER", "  OpenAI  ")
        monkeypatch.setenv("PENAGE_E2E_LLM_MODEL", "gpt-4o-mini")
        choice = detect_llm_choice()
        assert choice == LlmChoice(provider="openai", model="gpt-4o-mini")


class TestDetectSandboxBackend:
    def test_default_is_docker(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PENAGE_E2E_SANDBOX_BACKEND", raising=False)
        assert detect_sandbox_backend() == "docker"

    def test_env_override_null(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PENAGE_E2E_SANDBOX_BACKEND", "null")
        assert detect_sandbox_backend() == "null"

    def test_blank_env_falls_back_to_docker(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PENAGE_E2E_SANDBOX_BACKEND", "   ")
        assert detect_sandbox_backend() == "docker"
