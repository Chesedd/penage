from __future__ import annotations

import os
from argparse import Namespace
from dataclasses import dataclass
from pathlib import Path

from penage.core.guard import RunMode


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    base_url: str

    # LLM provider selection
    llm_provider: str
    llm_model: str

    # Ollama-specific (kept for backward compatibility and used when provider=ollama)
    ollama_model: str
    ollama_url: str

    trace_path: Path
    summary_path: Path | None

    mode: RunMode
    allow_static: bool

    actions_per_step: int
    max_steps: int
    max_http_requests: int
    max_total_text_len: int

    enable_specialists: bool
    policy_enabled: bool

    sandbox_backend: str
    docker_image: str
    docker_network: str

    experiment_tag: str
    allowed_hosts: tuple[str, ...]

    # Early-stop thresholds
    early_stop_tool_calls: int = 40
    early_stop_cost_usd: float = 0.30
    early_stop_seconds: float = 300.0

    # Stage 3.8 — correlation-based early stopping. None = signal disabled.
    max_no_evidence_steps: int | None = None
    max_policy_source_streak: int | None = None
    max_action_repeat_ratio: float | None = None
    action_repeat_window: int = 10

    # Memory store
    memory_db_path: str = "runs/memory.sqlite"

    # IDOR multi-role credentials. Empty string means "role not configured"
    # and IdorSpecialist's phase 2/3 will be skipped with a note.
    idor_role_a_user: str = ""
    idor_role_a_pass: str = ""
    idor_role_b_user: str = ""
    idor_role_b_pass: str = ""
    idor_login_url: str = ""

    # MAPTA-style multi-agent (Stage 3) — consumers wired in 3.3/3.7/3.8/3.9.
    sandbox_concurrency: int = 2
    correlation_stop_enabled: bool = True
    validation_mode: str = "http"

    # Stage 3.7 — parallel delegation across specialists via asyncio.gather.
    # Ablation-compatible: set to False to fall back to the sequential path.
    parallel_specialists: bool = True


def _idor_cred_from_args_or_env(
    args: Namespace,
    *,
    arg_name: str,
    env_name: str,
) -> str:
    val = str(getattr(args, arg_name, "") or "")
    if val:
        return val
    return os.environ.get(env_name, "")


def runtime_config_from_args(args: Namespace) -> RuntimeConfig:
    summary_path = Path(args.summary_json) if getattr(args, "summary_json", "") else None

    provider = str(getattr(args, "llm_provider", "ollama") or "ollama")
    llm_model = str(getattr(args, "llm_model", "") or "")

    ollama_model = str(getattr(args, "ollama_model", "") or "")
    ollama_url = str(getattr(args, "ollama_url", "") or "http://localhost:11434")

    # Backward-compat: if provider is ollama and llm_model is empty, fall back to --ollama-model
    if provider == "ollama" and not llm_model:
        llm_model = ollama_model

    idor_role_a_user = _idor_cred_from_args_or_env(
        args, arg_name="idor_role_a_user", env_name="PENAGE_IDOR_ROLE_A_USER"
    )
    idor_role_a_pass = _idor_cred_from_args_or_env(
        args, arg_name="idor_role_a_pass", env_name="PENAGE_IDOR_ROLE_A_PASS"
    )
    idor_role_b_user = _idor_cred_from_args_or_env(
        args, arg_name="idor_role_b_user", env_name="PENAGE_IDOR_ROLE_B_USER"
    )
    idor_role_b_pass = _idor_cred_from_args_or_env(
        args, arg_name="idor_role_b_pass", env_name="PENAGE_IDOR_ROLE_B_PASS"
    )
    idor_login_url = _idor_cred_from_args_or_env(
        args, arg_name="idor_login_url", env_name="PENAGE_IDOR_LOGIN_URL"
    )

    return RuntimeConfig(
        base_url=str(args.base_url),
        llm_provider=provider,
        llm_model=llm_model,
        ollama_model=ollama_model,
        ollama_url=ollama_url,
        trace_path=Path(args.trace),
        summary_path=summary_path,
        mode=RunMode(args.mode),
        allow_static=bool(args.allow_static),
        actions_per_step=int(args.actions_per_step),
        max_steps=int(args.max_steps),
        max_http_requests=int(args.max_http_requests),
        max_total_text_len=int(args.max_total_text_len),
        enable_specialists=bool(args.enable_specialists),
        policy_enabled=(str(args.policy) == "on"),
        sandbox_backend=str(args.sandbox_backend),
        docker_image=str(args.docker_image),
        docker_network=str(args.docker_network),
        early_stop_tool_calls=int(getattr(args, "early_stop_tool_calls", 40) or 40),
        early_stop_cost_usd=float(getattr(args, "early_stop_cost", 0.30) or 0.30),
        early_stop_seconds=float(getattr(args, "early_stop_seconds", 300.0) or 300.0),
        max_no_evidence_steps=(
            int(getattr(args, "max_no_evidence_steps"))
            if getattr(args, "max_no_evidence_steps", None) is not None
            else None
        ),
        max_policy_source_streak=(
            int(getattr(args, "max_policy_source_streak"))
            if getattr(args, "max_policy_source_streak", None) is not None
            else None
        ),
        max_action_repeat_ratio=(
            float(getattr(args, "max_action_repeat_ratio"))
            if getattr(args, "max_action_repeat_ratio", None) is not None
            else None
        ),
        action_repeat_window=int(getattr(args, "action_repeat_window", 10) or 10),
        memory_db_path=str(getattr(args, "memory_db", "runs/memory.sqlite") or "runs/memory.sqlite"),
        experiment_tag=str(getattr(args, "experiment_tag", "") or ""),
        allowed_hosts=tuple(str(x) for x in getattr(args, "allowed_host", []) or []),
        idor_role_a_user=idor_role_a_user,
        idor_role_a_pass=idor_role_a_pass,
        idor_role_b_user=idor_role_b_user,
        idor_role_b_pass=idor_role_b_pass,
        idor_login_url=idor_login_url,
        sandbox_concurrency=int(args.sandbox_concurrency),
        correlation_stop_enabled=not bool(args.no_correlation_stop),
        validation_mode=str(args.validation_mode),
        parallel_specialists=not bool(getattr(args, "no_parallel_specialists", False)),
    )
