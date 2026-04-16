# CAI + G-CTR — Cybersecurity AI: A Game-Theoretic AI for Guiding Attack and Defense

Mayoral-Vilches et al. (Alias Robotics / JKU Linz), 2026. `arXiv:2601.05887`.
Source: `docs/papers/cai.pdf` (file on disk was originally named `grpc.pdf`).

## Problem statement

AI-driven pentest agents (CAI, PentestGPT, AutoPT, VulnBot) produce overwhelming volumes of unstructured logs but lack the strategic intuition humans apply when they "play the game" — weighing attacker and defender payoffs at each step. Game-theoretic frameworks like Cut-the-Rope (CTR) compute optimal attacker/defender mixed strategies on attack graphs, but require manually-constructed graphs and have never been fused with live AI pentesting. The paper closes that loop: automatically extract attack graphs from agent logs, compute Nash equilibria, feed a digest back into the LLM's system prompt to anchor its subsequent actions.

## Architecture

Three phases running in a closed loop every ~5 agent interactions (~80 tool calls):

- **Phase 1 — G-CTR analysis.**
  - *LLM graph extraction.* The agent's recent trace is given to an LLM that emits JSON `{nodes, edges}`. Nodes carry `{id, name, info, vulnerability: bool, message_id}`. Preprocessing: merge entry points into `node_1`, cut incoming edges to it. Postprocessing: prune non-vulnerable leaves, add artificial leaf nodes (probability 1.0) after every vulnerable node. Graph size capped by piecewise-linear scaling against log length (12–16% of messages for <70 msgs, down to 3.5–5% for ≥200 msgs; clamped to [4, 25] nodes).
  - *Effort-based scoring.* Instead of CTR's hand-assigned exploit probabilities, edges carry an effort score ϕ ∈ [0, 1] combining message-distance, token count, and cost to reach the first vulnerable node.
  - *Nash solver.* Poisson attacker with rate λ_a=2, defender rate λ_d=1. Minimax LP over defender mixed strategy σ_d ∈ Δ(AS1). Returns `(defender_mix, attacker_paths, game_value)`. Under 5 ms for all tested graphs.
- **Phase 2 — Digest generation.** Two modes consuming the same Nash output:
  - *Algorithmic* — deterministic template using thresholds (high-risk transitions at p > 0.9, bottlenecks at p < 0.95); ~10 ms.
  - *LLM* — 350-word structured prompt, temperature 0.3, mean latency 28.3s ± 11.2s. Produces a markdown digest with Attack Paths, Bottlenecks, Critical Nodes, Tactical Guidance.
- **Phase 3 — Agent execution (ReAct).** Digest is injected into the **Coordinator's system prompt** (empirically better than user or assistant position). The old digest is replaced, not accumulated. Agent acts; new observations feed the next graph extraction.

## Key results

- **Graph extraction quality.** 70–90% node correspondence to expert annotations across five real-world exercises. 60–245× faster than manual graph construction, >140× cheaper.
- **Cyber-range (Shellshock CVE-2014-6271), 44 runs, 40-min cap, model alias1.**

  | Mode | n | Success | Avg duration | Tool variance | Cost/success |
  |---|---|---|---|---|---|
  | No G-CTR (baseline) | 15 | 13.3% | 16.7 min | 1.6× | $2.71 |
  | G-CTR algorithmic digest | 15 | 20.0% | 22.5 min | 6.2× | $0.32 |
  | G-CTR **LLM digest** | 14 | **42.9%** | 20.2 min | **1.2×** | **$0.12** |

  LLM digest: +29.6 pp over baseline (3.21× success probability), −2.67× expected time, 23× cheaper per success, 5.2× lower tool-use variance.
- **Attack-and-Defense CTFs.** "Purple G-CTR_merged" (red and blue share one graph + context) wins pingpong 52.4% vs 28.6% (~1.8:1) against LLM-only baseline, and cowsay 55% vs 15% (~3.7:1) against independently guided teams. Purely offensive prompting is net-negative (33.3% wins vs 42.9% losses).
- **Overhead.** Game-theoretic computation <5 ms; bottleneck is entirely LLM inference.

## What penage adopts

G-CTR is the blueprint for penage Stage 4:

- **LLM-based attack graph extraction every N steps** (Stage 4.1–4.2, `penage/graph/builder.py`, `penage/graph/llm_extractor.py`). Default N=5, pydantic-validated JSON schema, piecewise-linear node cap clamped to [4, 25] — copied directly.
- **Graph sanitization** — merge starting nodes into `node_1`, drop incoming edges to it, prune non-vulnerable leaves, add artificial probability-1 leaves after vulnerable nodes (Stage 4.1, `penage/graph/sanitize.py`).
- **CTR solver** (Stage 4.3, `penage/graph/ctr_solver.py`). Poisson with λ_a=2/λ_d=1 from the paper; LP minimax via `scipy`; returns `CTRResult(defender_mix, attacker_paths, game_value)`. Includes the degenerate-path special cases from §3.2.
- **Effort scoring** (Stage 4.4, `penage/graph/effort.py`). Formulas ϕ_msg, ϕ_tok, ϕ_cost from §3.1.3 with configurable simplex weights. For local-model runs (Ollama) `w_cost = 0` by default.
- **Dual-mode digest generator** (Stage 4.5, `penage/graph/digest.py`). Algorithmic mode for fast/deterministic; LLM mode at temperature 0.3 with algorithmic fallback on failure. Markdown sections match the paper (Attack Paths / Bottlenecks / Critical Nodes / High-Risk Transitions / Tactical Guidance).
- **Digest injection into Coordinator's *system* prompt** (Stage 4.6). CAI §3.2 footnote 2's empirical finding is taken as law.
- **A/B experiment harness** (Stage 4.7, `penage/experiments/ab.py`) — four configurations matching the paper's protocol; variance is a first-class reported metric.
- **Optional Purple / A&D mode** (Stage 6). Shared graph across red/blue agents; cowsay / pingpong scenarios as comparison points.

## What penage intentionally does NOT adopt

- **Alias1 / alias0 as reference models.** CAI's headline numbers depend on proprietary Alias models. penage uses Anthropic / OpenAI / Ollama through a shared protocol; reproducing CAI's Shellshock numbers is a Stage 4.7 A/B experiment, not a structural commitment.
- **CAI's broader framework.** We adopt only the G-CTR guidance layer — not the full CAI ReAct agent, Human-In-The-Loop tooling, or its bug-bounty workflow.
- **Accumulating digests across invocations.** The paper replaces the previous digest entirely; penage does the same. No append-only digest history.
- **3,600× human-speedup claim as a target.** Marketing number; not something we chase architecturally.
- **Digest in user or assistant prompt position.** CAI found empirically worse; penage enforces system-prompt injection only.
- **LLM graph extraction below the entropy floor.** CAI notes that generating a graph when the trace has fewer than ~3 vulnerable paths just injects noise. penage mirrors this: no digest injection until the graph has enough vulnerable paths to matter.
- **Closed-source game-theory solver dependencies.** Stick to `networkx` + `scipy`; no proprietary optimizers.
