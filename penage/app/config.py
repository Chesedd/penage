from __future__ import annotations

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


def runtime_config_from_args(args: Namespace) -> RuntimeConfig:
    summary_path = Path(args.summary_json) if getattr(args, "summary_json", "") else None

    provider = str(getattr(args, "llm_provider", "ollama") or "ollama")
    llm_model = str(getattr(args, "llm_model", "") or "")

    ollama_model = str(getattr(args, "ollama_model", "") or "")
    ollama_url = str(getattr(args, "ollama_url", "") or "http://localhost:11434")

    # Backward-compat: if provider is ollama and llm_model is empty, fall back to --ollama-model
    if provider == "ollama" and not llm_model:
        llm_model = ollama_model

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
        experiment_tag=str(getattr(args, "experiment_tag", "") or ""),
        allowed_hosts=tuple(str(x) for x in getattr(args, "allowed_host", []) or []),
    )
