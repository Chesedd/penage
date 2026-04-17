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

## Golden-trace snapshots

Regression guards for episode trace shape live under
`tests/golden/traces/*.json` and are driven by the harness at
`tests/support/golden_trace.py`.

- Run normally: `pytest -q tests/integration/golden/` — tests fail on any
  drift from the committed golden files.
- Regenerate: `PENAGE_UPDATE_GOLDEN=1 pytest -q tests/integration/golden/`
  rewrites the JSON files in place. Review the diff before committing;
  the env var is never set in CI.

## Security note

This repository should be used only for authorized targets.
When contributing examples or docs, keep them safe, reproducible, and clearly scoped to local labs or internal training environments.
