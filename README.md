# penage

`penage` is an agent-style runtime for authorized web security and CTF-style targets.
It combines an LLM planner, deterministic specialists, a policy layer, HTTP/sandbox tool backends,
validation, tracing, and execution summaries in a single episode loop.

> **Authorized use only.** This project is intended for local labs, CTFs, internal training targets,
> and explicitly authorized security testing.

## What the project does

A single episode roughly looks like this:

1. Build a runtime from CLI config.
2. Start an `Orchestrator` episode.
3. Ask specialists for candidate actions.
4. Ask the planner/LLM for the next action plan.
5. Let the policy layer choose between LLM and specialist proposals.
6. Execute actions through HTTP, sandbox, or macro backends.
7. Update state, validate evidence, write trace events, and emit a summary.

The project is designed around a few main ideas:

- **Planner + specialists** instead of a pure LLM loop.
- **Policy arbitration** between multiple action sources.
- **Strict execution modes** (`safe-http` and `sandboxed`).
- **JSONL trace + structured summary** for reproducibility.
- **Composable layers**: `core`, `tools`, `policy`, `specialists`, `macros`, `sandbox`, `validation`.

## Repository layout

```text
penage/
  app/          runtime wiring, CLI, summary building
  core/         state, planner, orchestrator, guards, tracing
  llm/          LLM interfaces and Ollama client
  macros/       reusable multi-step procedures
  policy/       ranking and action selection logic
  sandbox/      docker/null sandbox backends
  specialists/  deterministic and async candidate generators
  tools/        HTTP and sandbox tool execution
  utils/        shared parsing and helper functions
  validation/   evidence and validation logic

docs/
  architecture.md
  developer-guide.md
  user-guide.md

tests/
  unit/
  integration/
```

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com/) for local LLM inference
- Docker only if you want `--mode sandboxed --sandbox-backend docker`

## Installation

### Development install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .[dev]
```

### Minimal runtime install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

## Quick start

Run a single episode against a local lab target:

```bash
python -m penage.app.run_one \
  --base-url http://localhost:8080 \
  --ollama-model llama3.1 \
  --max-steps 20 \
  --trace runs/trace.jsonl \
  --summary-json runs/summary.json
```

Or use the thin wrapper at the repository root:

```bash
python run_one.py \
  --base-url http://localhost:8080 \
  --ollama-model llama3.1
```

## Execution modes

### `safe-http`

The default mode.

- Allows HTTP and NOTE actions only.
- No shell/python/macro execution outside the allowed guard set.
- Best choice for early debugging and low-risk runs.

### `sandboxed`

The execution-capable mode.

- Enables shell/python/macro actions.
- Can use Docker-backed sandbox execution.
- When sandboxed with Docker, the project uses the curl-based HTTP backend and rewrites localhost-style base URLs for container access.

Example:

```bash
python -m penage.app.run_one \
  --base-url http://localhost:8080 \
  --ollama-model llama3.1 \
  --mode sandboxed \
  --sandbox-backend docker \
  --docker-network bridge \
  --enable-specialists \
  --policy on
```

## Important CLI flags

- `--base-url` — target base URL.
- `--ollama-model` — Ollama model name.
- `--ollama-url` — Ollama server base URL.
- `--max-steps` — episode step budget.
- `--trace` — path to JSONL trace.
- `--summary-json` — path to summary JSON.
- `--mode` — `safe-http` or `sandboxed`.
- `--allow-static` — allow fetching static assets.
- `--actions-per-step` — number of chosen actions per step.
- `--max-http-requests` — HTTP budget.
- `--max-total-text-len` — text budget.
- `--enable-specialists` — enable specialist proposal pipeline.
- `--policy` — `off` or `on`.
- `--sandbox-backend` — `null` or `docker`.
- `--allowed-host` — extra allowed HTTP host; repeatable.
- `--experiment-tag` — optional run label.

## Outputs

Each run can produce:

- a **JSONL trace** with action, observation, note, validation, macro, and summary events
- a **summary JSON** with experiment config, result counters, previews, and usage stats

By default, if `--summary-json` is not provided, the summary is written next to the trace file with a `.summary.json` suffix.

## Testing

penage uses pytest with marker-based test selection. The default suite is fast
and self-contained; heavier suites are opt-in behind markers.

### Test layout

| Category | Marker | Location | Runs by default |
|----------|--------|----------|-----------------|
| Unit | _(none / implicit)_ | `tests/unit/` | yes |
| Integration | `integration` | `tests/integration/` (excluding `e2e/`) | yes |
| E2E DVWA | `e2e_dvwa` | `tests/integration/e2e/` | **no** (deselected) |
| Slow / chromium | `integration_slow` | `tests/integration/` (chromium, playwright) | **no** (deselected) |

Markers are declared in `pytest.ini`. The default `addopts` value
(`-m "not integration_slow and not e2e_dvwa"`) deselects the heavy suites so
`python -m pytest -q` stays fast and CI-friendly.

### Running tests

Default suite (unit + integration, no chromium, no DVWA):

```bash
python -m pytest -q
```

Unit tests only:

```bash
python -m pytest -q tests/unit/
```

Integration tests, excluding E2E:

```bash
python -m pytest -q tests/integration/ --ignore=tests/integration/e2e
```

E2E suite against a running DVWA instance (requires Docker + `docker pull python:3.12`;
bring the stack up with `docker compose -f compose/e2e_dvwa.yml up -d` first):

```bash
python -m pytest -m e2e_dvwa tests/integration/e2e/ -o addopts= -v
```

Slow / chromium-launching integration checks:

```bash
python -m pytest -m integration_slow -o addopts= -v
```

Single test by name:

```bash
python -m pytest tests/unit/path/to/test_x.py::test_y -v
```

Convenience `make` targets wrap the same commands: `make test`, `make unit`,
`make integration`, `make e2e`, `make slow`.

For environment setup (SDKs, env vars, fresh sandbox install, E2E prerequisites)
see [CONTRIBUTING.md](CONTRIBUTING.md#development-setup) and the
"Opt-in E2E suites" / "Environment variables" sections therein.

## Documentation

- [Architecture](docs/architecture.md)
- [Developer guide](docs/developer-guide.md)
- [User guide](docs/user-guide.md)

## GitHub setup checklist

Before pushing the repository:

- remove local traces, summaries, and temp artifacts
- verify `.gitignore`
- verify no secrets/cookies/tokens are committed
- run `pytest -q`
- check that `python -m penage.app.run_one --help` works
- enable the GitHub Actions workflow in `.github/workflows/tests.yml`

## License

This starter pack assumes **MIT** as a simple default.
If you need Apache-2.0, GPL, or a proprietary internal license instead, replace `LICENSE` before publishing.
