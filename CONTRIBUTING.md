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
pip install -e .[dev]
pytest -q
```

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

## Security note

This repository should be used only for authorized targets.
When contributing examples or docs, keep them safe, reproducible, and clearly scoped to local labs or internal training environments.
