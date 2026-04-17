# Architecture

## Overview

`penage` is an agent-runtime for authorized web lab targets.
Its architecture is layered so that planning, execution, validation, and runtime wiring are separable.

At a high level, one episode looks like this:

```text
CLI / run_one
  -> runtime factory / bootstrap
  -> Orchestrator
     -> specialists propose candidates
     -> planner asks LLM for action plan
     -> policy ranks and selects actions
     -> tools/macros execute actions
     -> state updater projects observations into state
     -> validator records evidence
     -> tracer writes trace events
     -> summary builder emits final summary JSON
```

## Layer map

### `penage.app`

Responsible for startup and composition:

- parse CLI arguments
- build `RuntimeConfig`
- wire together sandbox, tools, LLM, specialists, macros, policy, and orchestrator
- build final summary JSON

Key modules:

- `config.py`
- `runtime_factory.py`
- `bootstrap.py`
- `run_one.py`
- `summary.py`

### `penage.core`

Contains the domain runtime:

- action and observation types
- planner
- orchestrator
- state and state update pipeline
- guard and URL filtering
- planner context generation
- tracing

Key modules:

- `actions.py`
- `observations.py`
- `state.py`
- `planner.py`
- `orchestrator.py`
- `state_updates.py`
- `tracer.py`

### `penage.tools`

Executes low-level actions.

Responsibilities:

- HTTP via `httpx`
- HTTP via curl inside sandbox
- shell/python execution via sandbox
- routing actions to the right backend

Key modules:

- `http_tool.py`
- `curl_http_tool.py`
- `sandbox_tool.py`
- `runner.py`

### `penage.sandbox`

Sandbox implementations:

- `NullSandbox` — disabled sandbox backend
- `DockerSandbox` — isolated Docker execution backend
- `SandboxExecutor` — deterministic validator/helper wrapper around sandbox calls

### `penage.llm`

LLM abstraction layer:

- `base.py` — protocol and message/response types
- `fake.py` — deterministic testing client
- `ollama.py` — local Ollama client with JSON-oriented robustness features

### `penage.specialists`

Deterministic and async candidate generators.
They propose candidate actions based on current `State`.

Examples:

- `LoginWorkflowSpecialist`
- `NavigatorSpecialist`
- `ResearchSpecialist`
- `ResearchLLMSpecialist`
- `AuthSessionConfusionSpecialist`
- `CurlReconSpecialist`
- `SandboxSmokeSpecialist`
- `SsrfSpecialist` — five-phase SSRF probe (OOB canary via
  `shared.OobListener`, internal-target probing with latency
  baseline, LLM payload mutation, evidence-gated finalization).
  Emits `ssrf_oob` / `ssrf_metadata_leak` verified findings or an
  `ssrf_candidate` unverified finding (score 4.0) when only partial
  signals survive (5xx after scheme-bypass, outbound-latency hint).
- `CmdInjSpecialist` — AWE-pattern command-injection probe with
  echo-marker reflection, OS fingerprinting, OS-aware blind-timing
  (2-of-3 elapsed_ms consistency above the baseline), and LLM
  mutation of separators/encodings. Every outgoing payload — base,
  YAML-curated, or mutated — passes through `DestructiveCommandFilter`.
  Emits `cmdinj_echo` / `cmdinj_blind` verified findings, or
  `cmdinj_reflected_no_exec` / `cmdinj_timing_noise` / `cmdinj_blocked`
  candidates when only partial signals remain.
- `LfiSpecialist` — 5-phase (discovery → deterministic → bypass+mutation →
  OOB(php_filter+file_url) → candidate-finalize). Markers via
  `shared/path_traversal.detect_lfi_markers`.
- `XxeSpecialist` — 5-phase (discovery → classic SYSTEM → parameter-entity →
  OOB blind → candidate-finalize). Detection via
  `shared/xml_utils.detect_xxe_markers`; DoS-payload safety via
  `XmlSafetyFilter`.
- `IdorSpecialist` — 6-phase (login → discovery → horizontal differential →
  sequential enumeration → vertical privilege probe → candidate finalize).
  Evidence via `shared/differential.compare_responses` (body-hash equality,
  cross-owner PII markers, status spread). Multi-role session management via
  `shared/session_login.login_role` + `state.AuthRoleRegistry`. Purely
  deterministic; no LLM payload mutation (same rationale as XXE).

Manager and pipeline:

- `manager.py`
- `proposal_runner.py`
- `pipeline.py`

### `penage.policy`

Arbitrates between planner actions and specialist candidates.

Responsibilities:

- rank candidate actions
- penalize repeated/negative/failure-prone actions
- prefer pivot-aware or macro-consistent follow-ups
- select a diverse batch of actions

Key modules:

- `gctr_lite.py`
- `ranking.py`
- `selection.py`
- `scoring.py`
- `helpers.py`

### `penage.macros`

Reusable multi-step procedures.
Macros are higher-level execution primitives that hide repeated HTTP probing logic.

Current macro family:

- `replay_auth_session`
- `follow_authenticated_branch`
- `probe_resource_family`

Shared helpers:

- `probe_support.py`

### `penage.validation`

Validation and evidence logic.

Responsibilities:

- identify strong signals (for example flag-like output)
- suppress false positives such as static assets or login-gate pages
- record evidence/validated signals into state and trace

## Episode lifecycle in detail

### 1. Startup

`penage.app.run_one`:

- parses CLI args
- builds `RuntimeConfig`
- builds `JsonlTracer`
- calls `build_runtime(...)`
- starts one episode with a user prompt derived from the target base URL

### 2. Specialist proposal phase

If specialists are enabled, `SpecialistManager` collects candidate actions.
Those candidates are de-duplicated, source-capped, and previewed into `state.facts`.

### 3. Planner phase

`Planner` builds planner context from current `State`, sends messages to the LLM, parses JSON, and applies guard / URL filtering / negative-memory filtering.

### 4. Policy phase

If policy is enabled, `GctrLitePolicy` ranks both planner actions and specialist candidates, then selects a final action batch.

### 5. Execution phase

Actions are executed by:

- `ToolRunner` for HTTP / shell / python / notes
- `MacroExecutor` for macro actions

### 6. Projection and validation phase

Observations are projected back into state by the state update pipeline.
This updates things such as:

- known paths
- forms
- recent failures
- best HTTP page
- promoted pivots
- recent HTTP memory
- validation counters

### 7. Tracing and summary

Trace events are written as JSONL.
At the end of the episode, a structured summary JSON is written.

## Multi-agent architecture (Stage 3)

From Stage 3 onwards the runtime is organized as a MAPTA-style three-role
agent system. The `Orchestrator` is a bus that wires the roles together,
keeps per-episode state, and mediates every action + observation. Each role
runs with an isolated LLM context and its own usage accounting.

### Role diagram

```text
┌─────────────────────────────────────────────────────────────┐
│                      Orchestrator (bus)                     │
│  ┌─────────────────┐  ┌───────────────┐  ┌──────────────┐   │
│  │ CoordinatorAgent│  │ SandboxAgents │  │ValidationGate│   │
│  │   (planning)    │  │ (proxy × 7)   │  │              │   │
│  └────────┬────────┘  └───────┬───────┘  └──────┬───────┘   │
│           │                   │                 │           │
│           ▼                   ▼                 ▼           │
│    plan actions        propose via        validate obs      │
│       (role=coordinator)   Specialist     http → agent*     │
│                       (role=sandbox,                        │
│                       specialist=<name>)  *if mode=agent    │
└─────────────────────────────────────────────────────────────┘
                      │ run_episode (tracker bound via ContextVar)
                      ▼
              DockerSandbox (per-episode persistent)
              + HttpTool + MemoryStore + JsonlTracer
```

- **CoordinatorAgent** — high-level planner. Receives the observation +
  planner context, emits the next action plan. Only the coordinator role
  invokes the planner LLM. Role tag: `coordinator`.
- **SandboxAgent** — per-specialist LLM proxy. `build_sandbox_agents(llm)`
  creates one `RoleTaggedLLMClient` per specialist. `SpecialistManager`
  wires each LLM-driven specialist to its own proxy (never a shared client),
  so that token usage is attributed per specialist. Role tag: `sandbox`,
  with `specialist=<name>` in the per-specialist usage map.
- **ValidationAgent** — optional LLM escalator invoked by `ValidationGate`
  when the HTTP cascade is inconclusive. By contract the agent may only
  confirm or refute a candidate finding — never propose new ones. Role
  tag: `validation`.

### Flow of a single step

`run_episode → _run_step → _run_action`:

1. Budget + stop-condition + (optional) correlation early-stop checks run
   at the top of the step.
2. Specialists propose candidates in parallel via
   `SpecialistProposalRunner` (`asyncio.gather`), ablation-ready via
   `parallel_specialists=False`.
3. `CoordinatorAgent` picks actions (LLM-call under `role=coordinator`).
4. The policy layer arbitrates between planner actions and specialist
   candidates, producing the final batched action list.
5. `_run_action` executes each action in the batch:
   - `tools.run(...)` or `macros.run(...)` with the action fingerprint
     recorded in the `UsageTracker`.
   - The observation goes through `ValidationGate`: HTTP cascade first,
     then optional agent escalation when `validation_mode=agent`.
   - A memory attempt records the outcome for cross-episode reuse.

### Per-episode Docker hardening

In sandboxed mode the daemon container is created lazily on the first
exec and torn down in `try/finally` via `tools.aclose()` inside
`run_episode`. All sandbox calls inside the episode reuse the same
container. Hardening lives in
`DockerSandbox._base_docker_run_args`:

| Flag                    | Value                 | Purpose                          |
|-------------------------|-----------------------|----------------------------------|
| `--network none`        | (default)             | Network isolation                |
| `--read-only`           | rootfs read-only      | Tamper-resistant fs              |
| `--cap-drop ALL`        | —                     | Remove all Linux capabilities    |
| `--security-opt`        | no-new-privileges     | No suid escalation               |
| `--memory`              | `512m`                | RAM cap                          |
| `--memory-swap`         | = memory              | Disable swap bypass              |
| `--cpus`                | `1`                   | CPU share                        |
| `--pids-limit`          | `256`                 | Process cap (belt)               |
| `--ulimit nproc`        | `256:256`             | Process cap (suspenders)         |
| `--ulimit fsize`        | `64M:64M`             | Max file size (disk bomb guard)  |
| `--ulimit nofile`       | `256:256`             | Max open files                   |
| `--init`                | —                     | Zombie reaper                    |
| `--log-driver none`     | —                     | No log flooding                  |
| `--hostname`            | `penage-sandbox`      | No host leak                     |
| `--user`                | `1000:1000`           | Non-root                         |
| `--tmpfs /tmp`          | 64M, noexec, nosuid   | Ephemeral scratch                |
| `--tmpfs /workspace`    | 128M, nosuid          | Ephemeral workspace              |
| `-e HOME=/workspace`    | —                     | Writable HOME for non-root       |

`persistent=False` still exists as an ephemeral fallback (used in tests)
and applies the same hardening flags.

### Correlation-based early stopping

Three correlation signals sit on top of the raw cap thresholds. Each one
is ablation-ready via a `None` default.

- `max_no_evidence_steps` — stop after N consecutive steps without an
  increase in `validation_evidence_count`.
- `max_policy_source_streak` — cap on `state.same_policy_source_streak`
  (how long one policy source dominates selection).
- `max_action_repeat_ratio` — ratio of repeats in the last
  `action_repeat_window` actions.

Snapshots are taken in `UsageTracker.observe_step(state, step)` and
`UsageTracker.record_action_fingerprint(fp)`, and checked via
`check_early_stop(thresholds)` before each step.

### Ablation matrix

Every major lever in the multi-agent runtime is ablation-ready. Each of
these flags is exercised by `tests/integration/test_e2e_ablation.py`.

| CLI flag                           | Default    | Effect when disabled/altered           |
|------------------------------------|------------|----------------------------------------|
| `--validation-mode {http,agent}`   | `http`     | `agent` turns on LLM escalation in gate|
| `--no-parallel-specialists`        | off        | Specialists executed sequentially      |
| `--max-no-evidence-steps INT`      | `None`     | Correlation stop off when None         |
| `--max-policy-source-streak INT`   | `None`     | Correlation stop off when None         |
| `--max-action-repeat-ratio FLOAT`  | `None`     | Correlation stop off when None         |
| `--action-repeat-window INT`       | `10`       | Window for repeat-ratio                |
| `--mode {sandboxed, safe-http}`    | CLI-driven | sandboxed → DockerSandbox persistent;  |
|                                    |            | safe-http → NullSandbox / ephemeral    |

## Execution modes

## `safe-http`

Guard allows:

- `http`
- `note`

Use this mode when you want safer, narrower execution behavior.

## `sandboxed`

Guard allows:

- `http`
- `note`
- `shell`
- `python`
- `macro`

When combined with Docker sandboxing, localhost-like base URLs are rewritten for container access and the curl-based HTTP backend is used.

## Trace model

The tracer writes JSONL records for:

- `action`
- `observation`
- `note`
- `validation`
- `summary`
- macro sub-events in the macro-enabled runtime

This makes offline debugging and episode replay analysis much easier.

## Summary model

The summary JSON includes:

- experiment configuration
- result counters
- usage metrics
- previews of research, validation, auth confusion, and macro results

## Current extension points

Use these when extending the system:

- add a new specialist under `penage.specialists`
- add a new macro under `penage.macros`
- add a new policy implementation under `penage.policy`
- add a new validator or scoring tweak
- add new tool backends through the tool/runtime layer

## Known technical trade-offs

The current system is already significantly modularized, but there are still areas to watch:

- a substantial amount of cross-step metadata still flows through `State.facts`
- some specialists still rely on shell-heavy payload generation
- specialist completeness is uneven; some specialist stubs may still be intentionally minimal

Those trade-offs are acceptable for now, but should be documented for contributors before larger changes are made.
