# MAPTA — Multi-Agent Penetration Testing AI for the Web

David & Gervais (UCL), 2025. `arXiv:2508.20816`.
Source: `docs/papers/mapta.pdf`.

## Problem statement

Web security assessment faces a scalability crisis: up to 40% of AI-generated code contains vulnerabilities, and development outpaces manual/pattern-based auditing. Existing LLM pentest systems (PentestGPT, PenHeal, CAI, AutoPT) lack rigorous cost-performance accounting and frequently report theoretical findings without concrete PoCs. MAPTA argues that fully autonomous web pentesting is feasible if the system couples LLM orchestration with tool-grounded execution and mandatory end-to-end PoC validation.

## Architecture

Three agent roles driving a bounded loop, all sharing one per-job Docker container:

- **Coordinator Agent.** LLM-driven strategy and delegation. Tools: `sandbox_agent` (delegate), `run_command`, `run_python`, plus email workflow helpers (`get_registered_emails`, `list_account_messages`, `get_message_by_id`) and alerting (`send_slack_alert`, `send_slack_summary`). Holds the planning context; decides dynamically whether to execute directly or spin up sandbox agents.
- **Sandbox Agents (1..N).** Tactical execution with **isolated LLM contexts** but the same shared Docker container, so reconnaissance artifacts, credentials and dependencies persist across subtasks. Tools: only `run_command` and `run_python`. Run in threads for parallelism.
- **Validation Agent.** Consumes a candidate PoC (request sequence / payload / script), executes it concretely inside the container, returns pass/fail with evidence (flag capture for CTF; state change / data access / RCE for real-world). This is the gate that eliminates theoretical findings.

Resource handling is explicit: a per-scan `UsageTracker` records tool calls, latencies, LLM input/output/cached/reasoning tokens, cost, wall-clock time, and budget caps. Thread-local isolation, per-scan accounting. Two operating modes: **blackbox CTF** (single-agent, flag extraction as oracle) and **real-world whitebox** (full Coordinator + Sandbox + Validation).

Orchestration loop phases: hypothesis synthesis → targeted dispatch → PoC assembly → validation/finalization. Terminates on validated exploit or budget cap.

## Key results

Evaluated on 104-challenge XBOW benchmark (GPT-5) plus 10 real-world open-source apps (8K–70K stars).

- **Overall XBOW solve rate:** 76.9% (80/104) — within 7.7pp of XBOW's commercial claim of 84.6% while being open-source and reproducible.
- **Strong categories:** SSRF 100% (3/3), misconfiguration 100% (3/3), sensitive data exposure 100% (2/2), crypto 100% (1/1), SSTI 85% (11/13), SQLi 83% (5/6), broken authorization 83% (24/29), command injection 75% (6/8).
- **Weak categories:** XSS 57% (13/23), broken authentication 33% (1/3), blind SQLi 0% (0/3).
- **Cost accounting (total across 104 challenges):** 3.2M regular input + 50.5M cached + 1.10M output + 0.595M reasoning tokens, $21.38 total; median cost $0.073 per successful challenge vs $0.357 per failure. **Success correlates negatively with resource consumption** (r = −0.661 for tool calls, −0.606 for cost, −0.587 for tokens, −0.557 for time).
- **Early-stop thresholds derived empirically:** ~**40 tool calls**, **$0.30** per target, **300 seconds** — beyond these, success probability drops sharply.
- **Real-world impact:** 19 vulnerabilities across 10 apps, 14 classified high/critical, 10 pending CVE — at $3.67 average cost per assessment.
- **Limitations:** 43 of 104 XBOW Docker images were outdated and required patches to run.

## What penage adopts

MAPTA is penage's primary reference for orchestration and resource accounting:

- **Three-role split** — `CoordinatorAgent`, `SandboxAgent`, `ValidationAgent` (Stage 3, §3.1–3.2). Isolated LLM contexts per role, shared per-job sandbox.
- **Validation as a mandatory gate** (Stage 3.5). Findings are reported only after `ValidationGate.validate(finding)` returns pass. The CLAUDE.md invariant "no finding enters the summary as solved without validation" comes directly from MAPTA §2.3.
- **Per-job Docker isolation, per-scan accounting** (Stages 1.3–1.4 / `penage/core/usage.py`). The `UsageTracker` fields (`input_tokens`, `output_tokens`, `cached_tokens`, `reasoning_tokens`, `tool_calls`, `wall_clock_s`, `api_cost_usd`) mirror MAPTA's table verbatim.
- **Early-stop thresholds** (40 tool calls / $0.30 / 300s) — defaults in `EarlyStopThresholds` come from MAPTA's empirical analysis.
- **Backward-compat single-agent mode** (Stage 3.6) — `safe-http` stays single-agent; Coordinator-only with HTTP-only validation. Matches MAPTA's CTF mode.
- **Test matrix.** Stage 5 reruns MAPTA's XBOW evaluation and will reuse its 43 image patches.

## What penage intentionally does NOT adopt

- **Email/Slack workflow tools.** MAPTA's Coordinator has `get_registered_emails`, `list_account_messages`, `send_slack_alert`, etc. for real-world engagements. penage stays focused on the target application; no external tool side-effects.
- **Whitebox mode with source-code access.** penage is strictly blackbox at the orchestrator level. Whitebox inputs (if ever) belong in a pre-analysis step, not the agent loop.
- **Generic `run_command` at the Coordinator level.** MAPTA lets the Coordinator execute shell directly. penage keeps shell behind the Sandbox role to preserve the MAPTA invariant ("agent isolation") that MAPTA itself bends for CTF mode.
- **GPT-5 as the reference model.** MAPTA's numbers hinge on it. penage abstracts behind `LLMClient` and treats model choice as an experimental variable (Stage 5 ablations), not a dependency.
- **"Good enough" coverage of blind SQLi / XSS.** MAPTA's 0% on blind SQLi and 57% on XSS is the gap AWE fills — penage's Stage 2 specialists target those classes explicitly rather than relying on general reasoning.
