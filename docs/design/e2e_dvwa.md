# E2E DVWA suite — design note

Status: Stage 4.4.α design (investigation + design; no production code changes).
Owner: penage core. Consumers: Stage 4.4.β (fixtures + first scenarios),
Stage 4.4.γ (remaining scenarios + CI wiring).

## Scope

This note scopes the end-to-end suite that will prove `PlaywrightBrowser`
and `BrowserEvidenceValidator` actually drive a real chromium against a
real vulnerable target. In Stage 4.1.b the browser protocol, adapter and
evidence-gated XSS phase 5 landed, but nothing in CI has ever launched
chromium against a running HTTP server — the only browser tests live
under the `integration_slow` marker and exercise `data:` URLs, not
`page.goto(http://...)`. Stage 4.4 closes that gap by introducing a DVWA
target and a pytest suite that is **opt-in** (default-deselected), so
`pytest -q` stays the same 694-passed fast profile.

In scope for the full 4.4 arc (α/β/γ):

* a design doc for the suite and its fixture strategy (this file);
* a standalone chromium smoke script (landed in α at `scripts/smoke_chromium.py`);
* a pytest fixture exposing a running DVWA base URL to E2E tests (β);
* three to six scenarios covering reflected XSS, a baseline "no vuln"
  case, and (budget-permitting) stored XSS and SQLi (β/γ);
* a `Makefile` target that wraps the full `compose up → pytest → compose
  down` dance so local developers have a one-liner (γ).

Explicitly **out of scope** for 4.4:

* authenticated attack graphs across multiple vulnerabilities in one
  episode — that is Stage 5 benchmark work;
* CI execution on GitHub Actions — the suite is developer-triggered in
  4.4 and gets a dedicated CI job later;
* benchmark metrics collection (`benchmarks/dvwa.py`) — Stage 5.1;
* adding new vuln specialists to satisfy scenarios — if a specialist
  isn't ready, the scenario is deferred, not forced through.

## Fixture strategy

**Chosen: B (manual `docker compose up/down` + opt-in pytest marker),
with an optional `C`-style Makefile wrapper added in γ.**

Rationale in one paragraph: DVWA needs two containers (DVWA + MariaDB)
and a database-init POST after the app is up; driving that lifecycle
from inside pytest pulls in a dev-dep (`pytest-docker` or
`testcontainers`) that the project doesn't otherwise need, hides the
container state from the developer when something goes wrong, and makes
`pytest -q` slow or unsafe on any developer machine that happens to
have docker. Keeping the container lifecycle **outside** pytest and
behind an opt-in marker (`e2e_dvwa`) means (a) `pytest -q` continues to
skip the whole suite by default, (b) developers who want to run it do
the compose-up themselves and see every container error in the
foreground, and (c) CI just needs a shell script — no custom pytest
plugin. The Makefile wrapper in γ makes the common path `make e2e` so
the compose ceremony doesn't have to be memorized.

### A. pytest-docker automated

A `pytest-docker` fixture reads a `compose.yml` next to the tests,
starts the stack before the session, polls a health endpoint, yields
the base URL, and stops the stack on teardown. Module-scoped so it
survives all scenarios in one session.

Pros:

* single command: `pytest -m e2e_dvwa` does everything;
* automatic teardown even when tests are interrupted;
* CI config is literally the same command as local dev.

Cons:

* adds a dev-dep (`pytest-docker`, which itself depends on the `docker`
  SDK) that the project has zero other use for;
* lifecycle inside pytest → if compose-up fails, the failure surfaces
  as a fixture setup error and is awkward to debug;
* accidental `pytest -q` on a machine with docker *could* spin
  containers up even when the developer didn't intend it (we would
  mitigate with `@pytest.mark.e2e_dvwa`, but the dep is still loaded at
  collect time);
* compose + `docker` SDK both want their own version pins — one more
  vector for CI flakes.

### B. Manual compose up/down + opt-in marker (chosen)

Developer runs `docker compose -f tests/integration_e2e/dvwa/compose.yml up -d`,
then `pytest -m e2e_dvwa -o addopts=`, then `docker compose … down`. The
pytest fixture reads the DVWA base URL from an env var (e.g.
`PENAGE_E2E_DVWA_URL`, defaulting to `http://127.0.0.1:4280`) and
skips the session if the URL is unreachable.

Pros:

* zero new dev-deps;
* container state is transparent (`docker ps`, `docker compose logs`);
* trivial CI job — a bash script with three lines;
* perfectly safe on `pytest -q`: the `e2e_dvwa` marker is listed in
  `pytest.ini`'s `-m "not integration_slow and not e2e_dvwa"` after γ
  lands, and by default the target URL isn't even set;
* orthogonal to every other test profile — smoke-tests, golden, unit
  all stay exactly where they are.

Cons:

* developer friction: one extra command before `pytest`;
* no automatic teardown on ctrl-c — containers keep running until the
  developer explicitly `down`s them. Mitigated by Makefile wrapper in γ.

### C. Makefile-driven script

`make e2e` runs compose-up, then `pytest -m e2e_dvwa -o addopts=`,
then compose-down in a `trap` so teardown happens on success, failure,
or ctrl-c. Same underlying mechanics as B, but cheaper to invoke.

Pros:

* one command, no memorisation;
* still no new pytest-side dev-dep;
* easy for CI to reuse the same `make` target.

Cons:

* depends on `make`, which not every developer keeps installed on
  Windows (mitigated: everyone doing dev on penage uses Linux per the
  project's existing `Makefile`);
* compose-up errors are emitted by `docker compose` but interleaved
  with `pytest` output via the `trap` — marginally less clean than B
  standalone.

**Decision.** Use B as the primary mechanism. Add a Makefile `e2e`
target in γ that wraps B for convenience. Reject A because the added
dep/complexity isn't justified for a suite that runs only on demand.

## Scenarios

The table lists the scenarios the suite will grow into. Not every row
lands in β — β ships the reflected-XSS happy path and the baseline; the
others move in γ if their specialists and helpers are ready.

| # | Scenario | Endpoint | Specialist | Security | Expected level | Acceptance |
|---|----------|----------|------------|----------|----------------|------------|
| 1 | `xss_reflected_low` | `GET /vulnerabilities/xss_r/?name=<payload>` | `XssSpecialist` | `low` | `validated` (browser-proof) or `evidence` fallback | trace contains `xss_specialist.phase=5` event with `level ∈ {validated, evidence}`; summary findings list non-empty; reflection context one of `html_body` / `attr_quoted` / `attr_unquoted` |
| 2 | `no_vuln_baseline` | `GET /index.php` (logged in, security `low`) | full specialist manager | `low` | empty findings | `summary.findings == []`, no `level=validated` event in trace, episode exits on `max_steps` or early stop without false positive |
| 3 | `xss_stored_low` | `POST /vulnerabilities/xss_s/` then `GET` same path | `XssSpecialist` (needs stored-flow support — track in open questions) | `low` | `validated` (browser-proof) | XSS specialist submits payload via guestbook POST, then a second navigate yields a marker. If the specialist doesn't support stored flow, defer to Stage 5. |
| 4 | `sqli_low` | `GET /vulnerabilities/sqli/?id=1'` | `SqliSpecialist` | `low` | `validated` (evidence = row leak or deterministic timing) | trace contains `sqli_specialist` event with `evidence.rows` or `evidence.timing_ms`. Defer if specialist is still in heuristic mode. |
| 5 | `xss_reflected_medium` | same as #1 but DVWA security `medium` | `XssSpecialist` with `FilterInferrer` | `medium` | `evidence` (filter inference proves bypass) or `candidate` | `filter_model` in trace marks at least one tag/event as blocked; a bypass payload from the library still lands or the specialist records the filter profile. Optional; γ. |

Specialist-readiness matrix used to pick `β` vs `γ`:

* `XssSpecialist` — **ready**, used in golden traces (Stage 4.3),
  validated against execution-proof via `BrowserEvidenceValidator` in
  Stage 4.1.b.iii. Scenario 1 and the `no-vuln` baseline land in β.
* `SqliSpecialist` — present (664 LoC) with phase pipeline; validator
  branch in `ValidationGate` handles `http` mode; scenario 4 depends on
  whether a DVWA `low` SQLi (`id=1' OR '1'='1`) hits the existing
  detection logic. Verify in γ.
* Stored XSS in `XssSpecialist` — not covered in golden traces; needs
  audit. Track as an open question.

## CI integration

* **Marker.** Add `e2e_dvwa` to `pytest.ini` in β (**note:** 4.4.α does
  not touch `pytest.ini`; this is a β task). Register it next to the
  existing `integration_slow` / `docker` markers.
* **Default deselection.** Extend `addopts` to
  `-m "not integration_slow and not e2e_dvwa"`. `pytest -q` keeps the
  current 694-count fast profile.
* **Opt-in command.** `pytest -m e2e_dvwa -o addopts=` runs only the
  E2E suite (clearing the inherited deselection).
* **Makefile target.** γ adds `make e2e` which shells out to
  `docker compose -f tests/integration_e2e/dvwa/compose.yml up -d`,
  polls `/login.php` for readiness, runs the opt-in pytest command,
  and tears the compose stack down via a shell `trap`.
* **GitHub Actions job.** Deferred to Stage 5. When added, it will run
  `make e2e` inside the ubuntu-latest runner (which already has docker
  and compose preinstalled) and upload `runs/trace.jsonl` +
  `runs/summary.json` as artefacts on failure.

## Environment requirements

These are the prerequisites for running the E2E suite once β/γ land:

* **Docker CE 20.10+** with Compose V2. The DVWA compose stack uses
  `compose.yml` v3-ish syntax with dependency ordering.
* **Ports.** `127.0.0.1:4280` must be free on the host. Chosen because
  the upstream DVWA compose.yml binds to `127.0.0.1:4280:80`.
* **Playwright.** The `browser` extra (`pip install -e .[browser]`)
  plus `playwright install chromium` for the matching chromium build.
  The project pins `playwright>=1.40,<2.0`; pick a point release whose
  bundled chromium works on the target host.
* **System libraries.** Playwright's chromium needs a handful of X/NSS
  libraries; on Debian/Ubuntu, `python -m playwright install-deps
  chromium` covers them.
* **Sandbox caveat.** The 4.4.α investigation box has chromium
  `v1194` pre-installed under `/opt/pw-browsers/`. Playwright 1.58.0's
  default chromium is `v1208`, which the sandbox's network policy
  refused to fetch (`cdn.playwright.dev` not in the allowlist). Pinning
  `playwright>=1.56,<1.57` in the dev env made the pre-installed
  browser match and the smoke pass. β has to decide whether to pin
  `playwright==1.56.*` in the project's `browser` extra, whitelist
  `cdn.playwright.dev` in the sandbox, or both.
* **Rootless / `--no-sandbox`.** The smoke script launches chromium
  with `--no-sandbox --disable-dev-shm-usage` to work inside root
  containers. `PlaywrightBrowser` currently does **not** pass these
  flags — if the β CI job runs inside a rootful container it will need
  either a `--launch-args` knob on `PlaywrightBrowser` or a different
  sandbox configuration. Tracked as open question #3.
* **Chromium vs headless-shell.** Playwright 1.50+ offers
  `chromium_headless_shell` as a smaller default; the sandbox currently
  has `chromium-1194/chrome-linux/chrome` (full chrome). Either binary
  works with the stock launch call; the full binary is what
  `PlaywrightBrowser` is exercised against today.

## Open questions for β / γ

1. **Compose file location.** Where does `tests/integration_e2e/dvwa/compose.yml`
   live? Option A: ship a copy of DVWA's upstream `compose.yml` next to
   the tests (pinned image tag, reproducible). Option B: tell developers
   to `git clone` DVWA separately (less reproducible, less drift). β
   should pick A unless licensing objects.
2. **DVWA image tag.** Upstream publishes only `:latest` on
   `ghcr.io/digininja/dvwa`. Pinning by digest (e.g. `@sha256:…`) gives
   reproducibility at the cost of periodic refresh chores. β decides.
3. **`PlaywrightBrowser` sandboxing args.** Should production
   `PlaywrightBrowser.launch(…)` accept optional extra args (a list,
   default empty, enabling `--no-sandbox --disable-dev-shm-usage` in
   CI) or should the fixture swap in a subclass with a customised
   `_ensure`? β decides; preference is a typed kwarg on the constructor.
4. **Stored-XSS scenario feasibility.** `XssSpecialist`'s submit-then-
   fetch flow is not exercised in golden traces. β audits
   `penage/specialists/vulns/xss.py` for existing stored-flow support
   and either includes scenario #3 or documents the gap and defers.
5. **DB reset between scenarios.** DVWA stores stored-XSS payloads in
   MariaDB; stored scenarios pollute the guestbook across runs. Either
   call `setup.php → Create / Reset Database` between scenarios, or
   make each stored scenario idempotent by fingerprinting its payload.
6. **Auth flow ownership.** Who performs login + security-level
   selection — (a) the fixture, before yielding the URL (simple; cookies
   passed to penage via `State.auth_roles` or a config knob); or (b)
   `LoginWorkflowSpecialist` as part of the episode (closer to the
   production path, but couples the test to an unrelated specialist).
   Recommendation: fixture does it in β, specialist version becomes a
   separate scenario in γ once the end-to-end path is green.
7. **Rate-limit defaults.** DVWA under docker is slow to start and
   slow per-request. `RuntimeConfig.max_concurrent_per_host=4` should
   be fine; verify in β and either keep or drop to `2` for stability.
8. **`vulnerables/web-dvwa` vs `ghcr.io/digininja/dvwa`.** The existing
   `tests/integration/test_xss_dvwa.py` (Stage-era prototype, marked
   `docker` not `integration_slow`) uses the legacy `vulnerables/web-dvwa`
   single-image variant, while upstream now recommends the two-service
   compose at `ghcr.io/digininja/dvwa`. β aligns on the compose-based
   variant and decides whether to retire or retarget the existing
   prototype test.
9. **Makefile target name collision.** Current `Makefile` uses the
   target name space `install / install-dev / test / run-help`. γ adds
   `e2e`; confirm there is no shell-completion conflict with other
   developer tooling.
10. **CLI coverage vs programmatic episode.** `penage.cli.run_one` has
    the flags needed for DVWA (`--base-url`, `--enable-specialists`,
    `--policy on`, `--allowed-host 127.0.0.1`, `--trace …`), but β will
    likely prefer driving the orchestrator directly (like
    `tests/integration/test_e2e_safe_http.py` already does) so the test
    can assert against `State` rather than parsing summary JSON. Confirm
    in β.
