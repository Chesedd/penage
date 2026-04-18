# penage — Stage 5 roadmap

## Context

Stage 4 closed specific E2E coverage for DVWA XSS (reflected low/medium) and
SQLi (low, currently `xfail`). During stage 4 closure audits a number of
follow-on items were discovered that require stage 5 scope. This doc
consolidates them so the scattered "stage 5 note" comments sprinkled through
`CLAUDE.md`, `docs/design/e2e_dvwa_scenarios.md`, and inline TODOs have a
single authoritative landing page.

This is a **backlog catalog**, not a design RFC. Each item is a candidate
for a separate stage 5 intake ticket; deeper design work belongs to those
tickets.

## Work groups

### 1. SqliSpecialist + policy arbitration

Source: δ.β.2.b.i/ii/iii audits; CLAUDE.md "known limitations" entry on
specialist vs LLM rank arbitration.

#### 1.1 Policy score rebalancing

`_select_diverse` at `actions_per_step=1` returns only the top-scored action
(`penage/policy/selection.py:84-85`). Specialist NOTE actions currently
score 5.0 (unverified) or 11.0 (verified); LLM coordinator actions baseline
at 24.0. Net effect: specialist findings — even verified ones — can lose
rank competition and never commit.

Options:

- **(a)** Bump specialist base score so verified findings outrank LLM
  baselines.
- **(b)** Per-family floor so specialist findings always clear a minimum
  selection bar regardless of LLM score inflation.
- **(c)** `_select_diverse` k=1 seeding that reserves a slot for the top
  specialist action.
- **(d)** Raise default `actions_per_step` to 2 so the existing diversity
  logic (seeding best_spec + best_llm) becomes active by default.

Any combination of the above is viable; pick one in the intake ticket
after an ablation pass on the DVWA E2E trio.

#### 1.2 `_select_diverse` k=1 seeding bypass

`penage/policy/selection.py:84-85` — `if k <= 1: return ranked[:1]`. The
specialist-seeding branch (lines 91-111) is only reachable at `k >= 2`.
This means the diversity / floor mechanisms are silently inactive at the
CLI default, which is the surface behind §1.1 (d) above. Fix in
concert with the chosen rebalancing option.

#### 1.3 SQLi payload library enrichment

DVWA low schema is `users(user_id, first_name, last_name, user, password,
avatar)`. Current `error_extract` payloads in `penage/payloads/sqli.yaml`
do not reliably hit schema columns — e.g., `UNION SELECT user, password
FROM users-- -` works for DVWA but is not the first payload tried, and
the extractor regex covers version strings, not table data. Needed:

- `UNION SELECT` probes with column-count discovery (`ORDER BY N` stepping).
- MySQL `information_schema.tables` / `information_schema.columns`
  introspection payloads.
- Payload ranking tuned for DVWA layout as the common-case benchmark.

#### 1.4 Blind-timing SLEEP(5) propagation diagnostic

δ.β.2.b.iii trace observed `elapsed_ms` of 6–10 ms on SLEEP(5) probes
where ≥5000 ms was expected. Three-way diagnostic required to isolate
root cause:

- **Hypothesis A** — coordinator's httpx timeout short-circuits the
  request before the server sleeps. Check `HttpTool` per-request timeout
  and `RuntimeConfig.http_timeout_s`.
- **Hypothesis B** — payload rendering escapes / URL-encodes `SLEEP(5)`
  such that MySQL receives it as a string literal instead of a call.
- **Hypothesis C** — DVWA flushes the response buffer before the
  `SELECT SLEEP(5)` actually executes, so elapsed time reflects the
  flush, not the sleep. Verify by curling `'1' AND SLEEP(5)-- -`
  directly.

Fix is hypothesis-dependent; diagnostic can be a 1-hour standalone
investigation before scoping.

#### 1.5 `_attempted` dedup key normalization

`penage/specialists/vulns/sqli.py:191` — `key = f"{target.url}|
{target.parameter}"` treats `/path/` and `/path/?id=1` as different
targets because `target.url` is the full URL including query string.
A re-discovery with empty siblings then re-runs the pipeline: the step-4
regression in the δ.β.2.b.iii trace (baseline_ms 18→161,
`backend_hint` mysql→null) is the observable fingerprint.

Normalize via `urllib.parse.urlparse(target.url).path` (or
`(scheme, netloc, path)` tuple) for the dedup key while keeping the full
URL for HTTP emission.

#### 1.6 `CandidateAction.source` preservation through commit

The `source` attribution (specialist name, e.g., `"sqli"`) is currently
dropped when a `CandidateAction` is converted to a committed `Action` in
the orchestrator. Consequence: downstream trace consumers cannot
distinguish specialist-emitted actions from LLM-emitted ones post-commit.

Add a `candidates_proposed` trace event that captures the full ranked
list with `source` + `score` so later diagnostics can reconstruct why a
given action won arbitration.

#### 1.7 Remove SQLi E2E `xfail` marker

`tests/integration/e2e/test_dvwa_sqli_low.py` currently carries an
`@pytest.mark.xfail` pending §1.1 + §1.3 + §1.4. Remove the marker and
promote to hard-pass once those three items land and the trace shows
`verified=True` with extraction or blind-timing evidence.

### 2. XSS — stored + high security

Source: δ.α.2.c (stored XSS blocked); δ.α.1
(`FilterInferrer` case-mix gap); design doc section 3.3.

#### 2.1 Stored XSS support

Current `XssSpecialist` pipeline treats inject-URL and trigger-URL as the
same URL (phase 4 / phase 5 both reuse `probe_url`). DVWA stored XSS
requires POST-to-inject, GET-to-render. Options:

- **(a)** Extend `BrowserEvidenceValidator` to accept an optional
  `(inject_url, inject_method, inject_payload_params, trigger_url)`
  spec. Default `trigger_url = inject_url` preserves reflected behaviour.
- **(b)** Dedicated `XssStoredSpecialist` with its own inject-then-
  trigger pipeline; shares `PayloadMutator` + payload library + browser
  oracle. Keeps `XssSpecialist` focused on reflected flows.

Design-open issues tracked in `docs/design/e2e_dvwa_scenarios.md` §3.3.3
(cookie/session sharing between httpx and Playwright; DVWA guestbook
cleanup; parallel-run state isolation).

#### 2.2 `FilterInferrer` case-mix extension

`penage/specialists/shared/filter_inferrer.py` currently classifies
filters as byte-exact substring sets. DVWA XSS high uses
`preg_replace('/<(.*)s(.*)c(.*)r(.*)i(.*)p(.*)t/i', '', $name)` — a
regex-class filter where mixed-case and interstitial-character bypasses
(`<ScRiPt>`, `<sc<script>ript>`) defeat byte-level matching but succeed
semantically.

Model filters as regex classes (pattern + flags) rather than substring
sets. Payload mutator should then generate alt-tag variants
(`<img src=x onerror>`, `<svg onload>`) when a script-class filter is
inferred.

### 3. ValidationGate extension

Source: δ.α.1; δ.α.2.a.

#### 3.1 Gate routing for specialist phases 1–4

Currently only phase-5 / validation-emit actions route through
`ValidationGate`. Phase 1–4 HTTP probes bypass the gate and populate
their own inline state. Silent-skip for non-HTTP NOTE actions is
documented (see `docs/design/gate_routing_specialist_phases.md`), but
the HTTP probes in earlier phases should populate
`state.validation_results` uniformly for later graph reconstruction.

#### 3.2 SQLi-specific validator class

`SqliSpecialist` currently bypasses the gate entirely by emitting the
finding as an inline `NOTE` action. Refactor to a gate-routed
`SqliEvidenceValidator` for consistency with the XSS / SSTI / IDOR
validators. Pre-requisite for §3.1 landing cleanly.

### 4. Production sandbox + curl gap

Source: δ.β.2.a.

#### 4.1 curl availability in the default sandbox image

Production default sandbox image is `python:3.12-slim`
(`penage/cli/run_one.py:62`, `penage/sandbox/docker.py:15`). The
coordinator uses `curl` in early shell recon; slim does not ship
`curl`. The `python:3.12` override in E2E helpers works around this for
tests only.

Options:

- **(a)** Bump production default to `python:3.12` (full image). Cost:
  ~+500 MB per sandbox container.
- **(b)** Keep slim, add `curl` via apt bootstrap at sandbox startup.
  Cost: ~+5 s setup latency + requires outbound apt access, which
  conflicts with `--network none` hardening.
- **(c)** Build a custom `penage-sandbox` image with curated toolchain
  (curl, dnsutils, common pentest CLI bits). Publish to an internal
  registry or GHCR. Cost: image maintenance overhead; gain:
  reproducible tool surface + no runtime apt.

(c) is most consistent with MAPTA per-job Docker model; (a) is the
cheapest path to unblock coordinator recon in the near term.

### 5. Attack graph / G-CTR (deferred from stage 4.5)

Source: original stage 4.5 plan deferred during 4.4 closure.

#### 5.1 Gate routing design for multi-specialist coordination

Branch B deferred in 4.1.b.iii.γ. Requires attack-graph context to
decide routing priorities across concurrent specialists.

#### 5.2 Attack-graph traversal for multi-step exploits

Auth-flow + chained-vulnerability scenarios (e.g., SQLi → credential
extraction → authenticated XSS → stored payload). Needs the G-CTR
graph + Nash equilibrium + digest-injection pipeline from the CAI
paper. This is the main bulk of stage 5 effort if stage 5 kicks off
at the 4.5 deferral rather than §1.

#### 5.3 IDOR E2E test

`docs/design/e2e_dvwa_scenarios.md` carries an IDOR placeholder
(section reserved). `PENAGE_IDOR_*` env vars are already wired up
(discovered in 4.7.α). Work remaining: pick a DVWA target
(`/vulnerabilities/brute/` or similar), write the specialist
differential-test oracle, add the E2E scenario to
`tests/integration/e2e/`.

### 6. Compose / infra

Source: 4.7.γ lateral.

#### 6.1 Digest-pin compose images

`compose/e2e_dvwa.yml` currently references both DVWA and MariaDB by
`<repo>@sha256:<DIGEST_TBD>` placeholders. Real digests were not
resolvable in the 4.7.γ session (no outbound registry access). Resolve
locally via the commands in the compose-file header, commit the
concrete digests, and document a bump protocol (re-run E2E trio after
any digest change).

#### 6.2 Playwright / chromium version bump protocol

`pyproject.toml` pins `playwright>=1.40,<2.0`. Chromium itself is
installed via `playwright install chromium` post-dep. A bump requires:

- Re-running `playwright install chromium` in all dev environments.
- Revalidating the browser-verified XSS findings (reflected low /
  reflected medium) end-to-end.
- Updating the CONTRIBUTING setup bullet if the install command
  changes shape.

Document this in the stage 5 ticket and capture the protocol in
`CONTRIBUTING.md` once chosen.

## Tracking

Each item above corresponds to a separate ticket / issue at stage 5
intake. This doc is a snapshot — the authoritative source becomes the
issue tracker once items are ticketed.

## Cross-refs

- `CLAUDE.md` invariant #3 qualifier (SqliSpecialist phase deviation).
- `CLAUDE.md` invariant #4 qualifier (SQLi verified semantic).
- `CLAUDE.md` known technical debt — specialist vs LLM rank arbitration.
- `docs/design/e2e_dvwa_scenarios.md` §3.3 (stored XSS blocked).
- `docs/design/e2e_dvwa_scenarios.md` §3.4 (SQLi validator design).
- `docs/design/gate_routing_specialist_phases.md` (§3.1 context).
- δ.α.1 / δ.α.2 / δ.β.2.b.i/ii/iii audit prompts (investigation lineage).
