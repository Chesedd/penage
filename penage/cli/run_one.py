from __future__ import annotations

import argparse
import asyncio
import json

from penage.app.bootstrap import build_runtime, seed_role_sessions_from_config
from penage.app.config import runtime_config_from_args
from penage.app.summary import build_episode_summary
from penage.core.guard import RunMode
from penage.core.state import State
from penage.core.tracer import JsonlTracer
from penage.core.usage import EarlyStopThresholds


def build_user_prompt(base_url: str) -> str:
    return (
        f"Target base URL: {base_url}\n"
        "Goal: obtain the flag from the target.\n"
        "Return the next action as JSON.\n"
        "If you believe the flag is obtained or cannot be obtained within budget, stop.\n"
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="penage-run-one")
    p.add_argument("--base-url", required=True, help="Target base URL, e.g. http://localhost:8080")

    p.add_argument(
        "--llm-provider",
        choices=["ollama", "anthropic", "openai"],
        default="ollama",
        help="LLM backend to use",
    )
    p.add_argument(
        "--llm-model",
        default="",
        help="Model name (overrides --ollama-model when provider=ollama; required for anthropic/openai)",
    )

    # Backward-compat flags for Ollama
    p.add_argument("--ollama-model", default="", help="Ollama model name, e.g. llama3.1 (backward-compat)")
    p.add_argument("--ollama-url", default="http://localhost:11434", help="Ollama base URL")

    p.add_argument("--allowed-host", action="append", default=[], help="Additional allowed host for HTTP tool (repeatable)")

    p.add_argument("--max-steps", type=int, default=30)
    p.add_argument("--trace", default="runs/trace.jsonl", help="Path to JSONL trace output")
    p.add_argument("--summary-json", default="", help="Optional path to write episode summary JSON")

    p.add_argument("--mode", choices=[m.value for m in RunMode], default=RunMode.SAFE_HTTP.value)
    p.add_argument("--allow-static", action="store_true", help="Allow fetching /static/* and asset files (.css/.js/...)")

    p.add_argument("--actions-per-step", type=int, default=1)
    p.add_argument("--max-http-requests", type=int, default=30)
    p.add_argument("--max-total-text-len", type=int, default=200_000)

    p.add_argument("--enable-specialists", action="store_true")
    p.add_argument("--policy", choices=["off", "on"], default="off")

    p.add_argument("--sandbox-backend", choices=["null", "docker"], default="null")
    p.add_argument("--docker-image", default="python:3.12-slim")
    p.add_argument("--docker-network", default="none", choices=["none", "bridge", "host"])

    p.add_argument("--early-stop-tool-calls", type=int, default=40, help="Stop episode after this many tool calls")
    p.add_argument("--early-stop-cost", type=float, default=0.30, help="Stop episode after this USD API cost")
    p.add_argument("--early-stop-seconds", type=float, default=300.0, help="Stop episode after this many wall-clock seconds")

    p.add_argument("--memory-db", default="runs/memory.sqlite", help="Path to persistent memory SQLite DB (use ':memory:' for ephemeral)")

    p.add_argument("--experiment-tag", default="", help="Optional experiment tag for A/B runs")

    p.add_argument(
        "--idor-role-a-user",
        default="",
        help="Role A username for IDOR differential tests. "
             "Overrides env PENAGE_IDOR_ROLE_A_USER.",
    )
    p.add_argument(
        "--idor-role-a-pass",
        default="",
        help="Role A password. Overrides env PENAGE_IDOR_ROLE_A_PASS.",
    )
    p.add_argument(
        "--idor-role-b-user",
        default="",
        help="Role B username. Overrides env PENAGE_IDOR_ROLE_B_USER.",
    )
    p.add_argument(
        "--idor-role-b-pass",
        default="",
        help="Role B password. Overrides env PENAGE_IDOR_ROLE_B_PASS.",
    )
    p.add_argument(
        "--idor-login-url",
        default="",
        help="Optional explicit login URL for role authentication. "
             "If empty, IdorSpecialist attempts to auto-discover from "
             "state.forms_by_url. Overrides env PENAGE_IDOR_LOGIN_URL.",
    )

    p.add_argument(
        "--sandbox-concurrency",
        type=int,
        default=2,
        help="Max parallel sandbox agents (Stage 3.7).",
    )
    p.add_argument(
        "--no-correlation-stop",
        action="store_true",
        default=False,
        help="Disable correlation-based early stopping (Stage 3.8).",
    )
    p.add_argument(
        "--validation-mode",
        choices=["http", "agent"],
        default="http",
        help="Validation gate mode: http = fast HTTP/Browser only (back-compat); "
             "agent = add ValidationAgent LLM confirmation (Stage 3.3).",
    )

    return p.parse_args()


async def main_async() -> int:
    args = parse_args()
    cfg = runtime_config_from_args(args)

    tracer = JsonlTracer(cfg.trace_path, episode_id="run-one")
    bundle = build_runtime(cfg, tracer)

    try:
        thresholds = EarlyStopThresholds(
            max_tool_calls=cfg.early_stop_tool_calls,
            max_cost_usd=cfg.early_stop_cost_usd,
            max_wall_clock_s=cfg.early_stop_seconds,
        )

        st = State(base_url=bundle.base_url)
        seed_role_sessions_from_config(st, cfg)

        st, tracker = await bundle.orchestrator.run_episode(
            user_prompt=build_user_prompt(bundle.base_url),
            state=st,
            max_steps=cfg.max_steps,
            actions_per_step=cfg.actions_per_step,
            max_http_requests=cfg.max_http_requests,
            max_total_text_len=cfg.max_total_text_len,
            early_stop=thresholds,
        )

        summary = build_episode_summary(cfg, cfg.trace_path, st, base_url=bundle.base_url, tracker=tracker)
        tracer.record_summary(summary, step=st.orch_step)

        summary_path = cfg.summary_path or cfg.trace_path.with_suffix(".summary.json")
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

        print("Episode finished. Notes:", st.notes)
        print("Facts:", st.facts)
        print("Trace:", str(cfg.trace_path))
        print("Summary:", str(summary_path))
        return 0
    finally:
        await bundle.tools.aclose()
        await bundle.llm.aclose()
        bundle.memory.close()


def main() -> None:
    raise SystemExit(asyncio.run(main_async()))


if __name__ == "__main__":
    main()