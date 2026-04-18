"""Shared helper to build :class:`RuntimeConfig` for E2E DVWA tests.

Env-driven so dev machines without a specific LLM provider or a running
Docker daemon skip cleanly instead of crashing with obscure errors. The
two E2E scenarios share almost all configuration; scenario-specific
resource ceilings (``max_steps`` etc.) are passed as keyword arguments.

Public API:

* :class:`LlmChoice` — dataclass with the resolved provider + model.
* :func:`detect_llm_choice` — pure env-inspection helper, returns
  ``None`` if nothing usable.
* :func:`detect_sandbox_backend` — returns ``"docker"`` by default.
* :func:`build_dvwa_runtime_config` — high-level builder that calls
  :func:`pytest.skip` when prerequisites are missing.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import pytest

from penage.app.config import RuntimeConfig
from penage.core.guard import RunMode


ProviderName = Literal["openai", "anthropic", "ollama"]

# The full ``python:3.12`` image ships curl, which the coordinator's early
# shell-based recon relies on. Slimmer Python images lack curl and cause
# recon to abort with exit 127, masking downstream specialist signals.
_DEFAULT_SANDBOX_IMAGE = "python:3.12"


@dataclass(frozen=True)
class LlmChoice:
    """Resolved LLM provider/model pair for an E2E run."""

    provider: ProviderName
    model: str


def _default_model_for(provider: str) -> str:
    """Return the provider's ``DEFAULT_MODEL`` via lazy import.

    Lazy so a missing optional dep (``openai`` / ``anthropic``) only
    trips the code path that actually needs it. Ollama has no single
    default — callers must pass ``PENAGE_E2E_LLM_MODEL`` explicitly.
    """
    if provider == "openai":
        from penage.llm.openai import DEFAULT_MODEL  # noqa: PLC0415

        return DEFAULT_MODEL
    if provider == "anthropic":
        from penage.llm.anthropic import DEFAULT_MODEL  # noqa: PLC0415

        return DEFAULT_MODEL
    if provider == "ollama":
        return ""
    raise ValueError(f"unknown provider: {provider}")


def detect_llm_choice() -> LlmChoice | None:
    """Resolve provider + model from env, or ``None`` if nothing usable.

    Precedence:

    1. Explicit ``PENAGE_E2E_LLM_PROVIDER`` (+ optional
       ``PENAGE_E2E_LLM_MODEL``; provider's default otherwise).
    2. ``OPENAI_API_KEY`` present → ``openai`` with its ``DEFAULT_MODEL``.
    3. ``ANTHROPIC_API_KEY`` present → ``anthropic`` with its default.
    4. Otherwise ``None``.
    """
    provider = os.environ.get("PENAGE_E2E_LLM_PROVIDER", "").strip().lower()
    model = os.environ.get("PENAGE_E2E_LLM_MODEL", "").strip()

    if provider:
        if provider not in ("openai", "anthropic", "ollama"):
            raise ValueError(
                f"PENAGE_E2E_LLM_PROVIDER must be one of openai/anthropic/ollama, "
                f"got: {provider!r}"
            )
        if not model:
            model = _default_model_for(provider)
        return LlmChoice(provider=provider, model=model)  # type: ignore[arg-type]

    if os.environ.get("OPENAI_API_KEY"):
        return LlmChoice(
            provider="openai",
            model=model or _default_model_for("openai"),
        )
    if os.environ.get("ANTHROPIC_API_KEY"):
        return LlmChoice(
            provider="anthropic",
            model=model or _default_model_for("anthropic"),
        )
    return None


def detect_sandbox_backend() -> str:
    """Return sandbox backend name; default ``"docker"``.

    Override via ``PENAGE_E2E_SANDBOX_BACKEND``. Empty string also falls
    back to ``"docker"`` so a blank-but-present env var doesn't silently
    disable sandboxing.

    Supported values:

    * ``"docker"`` (default, production) — containerized sandbox execution.
      All hardening flags from ``DockerSandbox._base_docker_run_args`` apply
      (``--network none``, ``--read-only``, ``--cap-drop ALL``, etc.). This
      is the only backend appropriate for untrusted payloads.
    * ``"null"`` — no sandbox; recon steps that require shell execution are
      skipped upstream. **DEV ONLY** convenience for fast E2E iteration on
      hosts without a reachable Docker daemon. Do not use against untrusted
      targets — there is no isolation boundary.

    Production deployments always resolve to ``"docker"``: the helper default
    is ``"docker"``, the prod ``RuntimeConfig`` default is ``"docker"``, and
    CI keeps the env var unset so this default applies.
    """
    raw = os.environ.get("PENAGE_E2E_SANDBOX_BACKEND", "").strip()
    return raw or "docker"


def _docker_reachable() -> bool:
    """Best-effort reachability probe for the local Docker daemon.

    Runs ``docker info --format {{.ServerVersion}}`` with a tight
    timeout. Returns ``False`` on any failure mode (CLI missing, daemon
    not up, slow response) — callers translate that into a skip.
    """
    try:
        res = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False
    return res.returncode == 0 and res.stdout.strip() != ""


def build_dvwa_runtime_config(
    base_url: str,
    trace_path: Path,
    *,
    target_url: str,
    allowed_host: str,
    experiment_tag: str,
    max_steps: int = 12,
    max_http_requests: int = 60,
    max_total_text_len: int = 400_000,
    actions_per_step: int = 1,
) -> RuntimeConfig:
    """Build a :class:`RuntimeConfig` for a DVWA E2E scenario.

    Calls :func:`pytest.skip` (never raises) when:

    * No LLM credentials are present and no explicit override is set.
    * ``PENAGE_E2E_LLM_PROVIDER=ollama`` without ``PENAGE_E2E_LLM_MODEL``.
    * Sandbox backend resolves to ``"docker"`` but the daemon is
      unreachable — set ``PENAGE_E2E_SANDBOX_BACKEND=null`` to force a
      null sandbox (note: shell-based recon won't run).

    ``base_url`` keeps the parameter shape parallel to the old
    ``_build_cfg`` call-sites; only ``allowed_host`` is actually used
    from it by callers today.
    """
    del base_url  # retained for call-site parity; allowed_host is what we need
    llm = detect_llm_choice()
    if llm is None:
        pytest.skip(
            "No LLM credentials for E2E. Set OPENAI_API_KEY or "
            "ANTHROPIC_API_KEY, or set PENAGE_E2E_LLM_PROVIDER "
            "(+ PENAGE_E2E_LLM_MODEL) explicitly."
        )
    if llm.provider == "ollama" and not llm.model:
        pytest.skip(
            "PENAGE_E2E_LLM_PROVIDER=ollama requires PENAGE_E2E_LLM_MODEL."
        )

    sandbox_backend = detect_sandbox_backend()
    if sandbox_backend == "docker" and not _docker_reachable():
        pytest.skip(
            "Docker daemon unreachable for E2E sandbox. Start Docker "
            "Desktop or set PENAGE_E2E_SANDBOX_BACKEND=null (skips "
            "recon-via-shell; XSS probing may not trigger)."
        )

    return RuntimeConfig(
        base_url=target_url,
        llm_provider=llm.provider,
        llm_model=llm.model,
        ollama_model=llm.model if llm.provider == "ollama" else "",
        ollama_url=os.environ.get(
            "PENAGE_E2E_OLLAMA_URL", "http://localhost:11434"
        ),
        trace_path=trace_path,
        summary_path=None,
        mode=RunMode.SAFE_HTTP,
        allow_static=False,
        actions_per_step=actions_per_step,
        max_steps=max_steps,
        max_http_requests=max_http_requests,
        max_total_text_len=max_total_text_len,
        enable_specialists=True,
        policy_enabled=True,
        sandbox_backend=sandbox_backend,
        docker_image=_DEFAULT_SANDBOX_IMAGE,
        docker_network="none",
        experiment_tag=experiment_tag,
        allowed_hosts=(allowed_host,),
        browser_verification=True,
        browser_launch_args=("--no-sandbox", "--disable-dev-shm-usage"),
    )
