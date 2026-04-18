# Contributing

Thanks for contributing.

## Ground rules

- Keep the package structure under `penage/`.
- Add tests with every non-trivial change.
- Prefer small, reviewable pull requests.
- Do not commit secrets, cookies, traces, summaries, or local lab data.
- Do not reintroduce proxy modules that only re-export root files.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev]" anthropic openai
python -m pytest -q
```

Notes for a fresh sandbox / fresh dev environment:

- Run `pip install -e ".[dev]" anthropic openai`. The `anthropic` and `openai`
  SDKs are not pinned in `[dev]` extras but are required by LLM-backed tests.
  Without them, ~7+ tests will ImportError.
- Use `python -m pytest`, not bare `pytest`. The latter is vulnerable to PATH
  shadowing in some sandbox environments (mismatched venv resolution).
- Default remote branch is `master` (not `main`).

## Branching

Suggested branch naming:

- `feature/<name>`
- `fix/<name>`
- `refactor/<name>`
- `docs/<name>`
- `test/<name>`

## Commit style

Suggested commit prefixes:

- `feat:`
- `fix:`
- `refactor:`
- `test:`
- `docs:`
- `chore:`

Examples:

- `refactor: split state update pipeline into components`
- `test: add integration coverage for macro execution`
- `docs: add architecture and user guides`

## Pull request checklist

Before opening a PR:

- [ ] `pytest -q` passes
- [ ] new logic has unit/integration coverage as appropriate
- [ ] docs are updated if behavior changed
- [ ] no generated traces or summary artifacts are committed
- [ ] no secrets/tokens/cookies are committed
- [ ] CLI/help still works if startup code changed

## Test organization

Put tests in:

- `tests/unit/...` for isolated unit tests
- `tests/integration/...` for multi-component behavior

Then group by domain:

- `tests/unit/core/...`
- `tests/unit/policy/...`
- `tests/unit/tools/...`
- `tests/integration/macros/...`
- etc.

### Opt-in E2E suites

Heavy end-to-end suites are behind pytest markers and default-deselected so
`pytest -q` stays fast:

- `e2e_dvwa` — drives a full episode against a live DVWA. Bring the stack
  up with `docker compose -f compose/e2e_dvwa.yml up -d`, then run
  `pytest -m e2e_dvwa tests/integration/e2e/ -o addopts= -v`. Tests skip
  automatically if `DVWA_BASE_URL` (default `http://127.0.0.1:4280`)
  isn't reachable.
- `integration_slow` — chromium-launching integration checks. Run with
  `pytest -m integration_slow -o addopts=`.

In rootful Docker / Linux CI, set
`RuntimeConfig.browser_launch_args=("--no-sandbox", "--disable-dev-shm-usage")`
(the E2E fixture already does) so chromium's own sandbox is disabled.

#### Required environment for E2E

E2E tests hit a real DVWA container and exercise the agent end-to-end,
so they need a working LLM and a Docker sandbox:

1. **LLM credentials** — set either `OPENAI_API_KEY` or
   `ANTHROPIC_API_KEY`. Auto-detection prefers OpenAI; override
   explicitly via `PENAGE_E2E_LLM_PROVIDER`
   (`openai` / `anthropic` / `ollama`) and `PENAGE_E2E_LLM_MODEL`.
   Default models come from `penage/llm/<provider>.py::DEFAULT_MODEL`.
2. **Docker Desktop** running — required for the sandbox backend
   (shell-based recon). Set `PENAGE_E2E_SANDBOX_BACKEND=null` to fall
   back to the null sandbox (note: some recon actions won't run).
3. **Sandbox image prerequisite** — `docker pull python:3.12` before
   the first E2E run. The full image provides curl (which
   `python:3.12-slim` lacks); penage's coordinator uses curl-based
   shell recon in early steps.

   *Note:* Production sandbox defaults (`penage/cli/run_one.py:62`,
   `penage/sandbox/docker.py:15`) still reference `python:3.12-slim`.
   This is a known limitation (tracked in stage 5 backlog: production
   sandbox curl readiness). The E2E helper
   (`tests/support/e2e_config.py`) overrides to `python:3.12` for test
   reliability.
4. Bring DVWA up, run pytest, tear down:

   ```bash
   docker compose -f compose/e2e_dvwa.yml up -d
   pytest -m e2e_dvwa tests/integration/e2e/ -o addopts= -v
   docker compose -f compose/e2e_dvwa.yml down -v
   ```

Tests skip cleanly (not fail) when LLM credentials or the Docker
daemon are unavailable.

### Environment variables

Penage-specific env vars consumed by code and tests. Providers'
`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` are standard and documented
above; the table below covers `PENAGE_*` overrides.

| Variable | Purpose | Default |
|----------|---------|---------|
| `PENAGE_UPDATE_GOLDEN` | Regenerate golden trace files under `tests/integration/golden/` (use sparingly; commits trace deltas). Set to `1` to accept. | unset |
| `PENAGE_E2E_LLM_PROVIDER` | LLM provider override for E2E (`openai` / `anthropic` / `ollama`). | unset (auto-detect from `OPENAI_API_KEY` / `ANTHROPIC_API_KEY`, preferring OpenAI) |
| `PENAGE_E2E_LLM_MODEL` | LLM model identifier override for E2E. | provider's `DEFAULT_MODEL` (`penage/llm/<provider>.py`) |
| `PENAGE_E2E_SANDBOX_BACKEND` | Sandbox backend for E2E (`docker` / `null`). | `docker` |
| `PENAGE_E2E_OLLAMA_URL` | Ollama endpoint when `PENAGE_E2E_LLM_PROVIDER=ollama`. | `http://localhost:11434` |
| `PENAGE_IDOR_ROLE_A_USER` | IDOR specialist role-A username (paired with the `--idor-role-a-user` CLI flag). | unset |
| `PENAGE_IDOR_ROLE_A_PASS` | IDOR specialist role-A password. | unset |
| `PENAGE_IDOR_ROLE_B_USER` | IDOR specialist role-B username. | unset |
| `PENAGE_IDOR_ROLE_B_PASS` | IDOR specialist role-B password. | unset |
| `PENAGE_IDOR_LOGIN_URL` | IDOR login URL override (bypasses `state.forms_by_url` discovery). | unset |

## Security note

This repository should be used only for authorized targets.
When contributing examples or docs, keep them safe, reproducible, and clearly scoped to local labs or internal training environments.
