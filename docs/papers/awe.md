# AWE — Adaptive Web Exploitation

Jaswal & Baghel (Stux Labs), LAST-X 2026. `arXiv:2603.00960`.
Source: `docs/papers/awe.pdf`.

## Problem statement

AI-assisted development is outpacing the adaptability of existing security tooling. Pattern-driven scanners (Burp, ZAP, Nuclei, sqlmap) cannot synthesize novel payloads against non-standard sanitization or adaptive WAFs, and general-purpose LLM agents explore without structure — high cost, unstable behavior, poor reproducibility, many false positives. AWE argues that injection-class exploitation needs domain-specific pipelines grounded by concrete behavioral evidence, not unconstrained reasoning.

## Architecture

Three layers, all sharing a unified state model:

- **Orchestration Layer.** An "Intelligent Orchestrator" holds the global exploitation context (inputs discovered, server transformations, auth status, prior attempts, successes). LLM converts recon output into a prioritized plan that selects a minimal subset of specialist agents to invoke. Enforces token/runtime/cost budgets and can early-stop.
- **Specialized Agents Layer.** One agent per vulnerability class. XSS is the flagship example — a five-phase pipeline: (1) parallel canary injection, (2) reflection context analysis (attribute-quoted, JS string, HTML body, …), (3) filter/tag/event/encoding inference, (4) LLM-conditioned payload mutation grounded by the inferred filter model, (5) verification. SQLi, SSTI, command injection, XXE, SSRF, IDOR, LFI follow the same shape (differential testing for IDOR, engine-specific probes for SSTI, timing statistics for blind SQLi).
- **Foundation Layer.** Persistent Memory (short-term scan state: payloads tried, filter models, markers; long-term cross-target: effective bypasses, sanitization signatures, payload success rates). Browser Verification Engine (headless execution observing dialogs, console events, DOM mutations — definitive evidence for XSS). Endpoint discovery, parameter extraction, technology fingerprinting.

Design rationale: specialization over generalized reasoning; stateful memory-driven operation; verification rather than speculation.

## Key results

Evaluated on 104-challenge XBOW benchmark against MAPTA.

- **Overall solve rate:** AWE 51.9% (54/104) with Claude Sonnet 4; MAPTA 76.9% (80/104) with GPT-5.
- **Injection wins for AWE:** XSS 87% (20/23) vs MAPTA 57%; blind SQLi 67% (2/3) vs 33%; SQLi 100% vs 100%; XXE 100% vs 100%; SSRF 100% vs 100%. MAPTA leads on SSTI (85% vs 54%) and command injection (82% vs 45%).
- **Efficiency:** AWE 1.12M tokens vs MAPTA 54.9M (~98% reduction); total cost $7.73 vs $21.38 (~63% reduction); median solve 35.7s vs 156.2s (~4.4× faster).
- **DVWA payload iterations to solve:** Claude Sonnet 4 converges ~10 payloads on Low difficulty, ~40 on Hard — the most efficient model tested (20% fewer iterations than GPT-4o, 40% fewer than Gemini 2.0 Flash).
- **Failure modes for AWE:** half of failed challenges required multi-step reasoning or business logic — categories MAPTA's general-purpose reasoning handles better.

## What penage adopts

Most of AWE's architecture maps directly to penage's stages:

- **Five-phase specialist pattern** (Stage 2, §2.4) — AWE's XSS pipeline is reproduced literally: canary injection → context analysis → filter inference → conditioned mutation → evidence-gated verification. AWE is the primary reference for `XssSpecialist`, `SqliSpecialist`, `SstiSpecialist`, `IdorSpecialist`.
- **Shared analysis modules** `reflection_analyzer`, `filter_inferrer` (Stage 2.1) come from AWE's shared Foundation Layer.
- **Browser verification** for XSS (Stage 2.2) — AWE §IV.B/§IV.C motivates Playwright-based verification as the anti-hallucination gate.
- **Hybrid payload generation** — small curated YAML sets + LLM mutation conditioned on the inferred filter model (Stage 2.3). Matches AWE §IV.B.
- **Persistent memory** (Stage 1.5 / `penage/memory/`) — AWE's short-term scan state and long-term cross-target tables correspond directly to our `scan_state` and `cross_target` SQLite tables.
- **Global resource budgets and early-stop** (Stage 1.3/1.4) — AWE's orchestrator budget/early-exit logic is the basis for `UsageTracker` + `EarlyStopThresholds`.

## What penage intentionally does NOT adopt

- **Tight coupling of memory and orchestrator.** AWE assumes all agents share a single in-process memory. penage keeps `MemoryStore` behind a thin interface (SQLite) so Stage 3 can replace per-agent memory scopes independently.
- **Claude Sonnet 4 as the reference model.** AWE's efficiency numbers depend on it, but penage supports Ollama, Anthropic, and OpenAI through a shared `LLMClient` protocol (Stage 1.2) — reproducing AWE's numbers is a Stage 5 ablation, not a structural assumption.
- **AWE's assumption of single-agent orchestration.** penage's Stage 3 splits roles (Coordinator / Sandbox / Validation) along MAPTA lines rather than keeping one global orchestrator. AWE's own limitations section flags single-agent planning as a weakness.
- **Closed-source XBOW patches, proprietary dataset assumptions.** penage's benchmarks (Stage 5) will document patches explicitly in `docker/xbow-patches/` rather than silently depend on upstream.
