# E2E DVWA scenarios — readiness survey

**Статус:** skeleton (Stage 4.4.δ.α.1).
**Область:** кандидаты E2E-расширения `tests/integration/e2e/` после δ.β: stored XSS,
SQLi, reflected XSS на security=medium.
**Ссылки:** `docs/design/e2e_dvwa.md`, `docs/design/gate_routing_specialist_phases.md`.

Этот документ — investigation-only survey. Он фиксирует, какие specialists,
validators и DVWA-prerequisites существуют **сегодня** (после 4.4.γ), и
разметит три кандидата как go/no-go/blocked до попытки их писать. Секции 3 и 4
(per-scenario detail, integrated plan) заполняет сессия δ.α.2 — здесь только
скелет.

## Section 1. Executive summary

После 4.4.γ в репе есть полнофункциональный `XssSpecialist` с 5-phase pipeline
и gate-shared browser-валидацией; `SqliSpecialist` с error-based +
blind-timing detection без отдельного oracle; generic `HttpEvidenceValidator`
+ `BrowserEvidenceValidator`; `dvwa_auth.authenticate(...)` хардкодит
`security=low`. Готовность кандидатов:

| # | Scenario | Decision | Primary blocker (если no-go/blocked) |
|---|----------|----------|--------------------------------------|
| 3 | Stored XSS (`/vulnerabilities/xss_s/`) | blocked | inject→trigger-page separation отсутствует в `XssSpecialist._discover_targets` и `_verify_candidates` (один и тот же URL для probe и browser-navigate). |
| 4 | SQLi (`/vulnerabilities/sqli/?id=...`) | go | — |
| 5 | XSS medium (`/vulnerabilities/xss_r/`, security=medium) | go | — (мелкий tweak: `dvwa_auth.authenticate` должен принимать `security_level`). |

## Section 2. Readiness matrix

| Criterion | #3 Stored XSS | #4 SQLi | #5 XSS medium |
|-----------|---------------|---------|---------------|
| 1. Specialist exists | `XssSpecialist` `penage/specialists/vulns/xss.py:81` — reused, но discovery / verification не разделяют injection-URL и trigger-URL. | `SqliSpecialist` `penage/specialists/vulns/sqli.py:104`. | `XssSpecialist` `penage/specialists/vulns/xss.py:81` (тот же, что и в #1). |
| 2. 5-phase coverage | `1✓ 2✓ 3✓ 4✓ 5✗` — phase 5 (`_verify_candidates` `xss.py:313-458`) навигирует browser на тот же `probe_url`; stored требует POST на `/xss_s/` и GET-navigate там же для рендера guestbook, что совпадает по URL, но специалист не различает «inject-request» от «trigger-request». | `1✓ 2✗ 3✓ 4✓ 5✓` — pipeline не-канонический: baseline (`sqli.py:281`), error-based fingerprint+extraction (`sqli.py:302`), blind-timing (`sqli.py:415`); нет отдельных context-analysis и filter-inference фаз (обосновано: SQL-контекст не парсится из reflection). | `1✓ 2✓ 3⚠ 4✓ 5✓` — `FilterInferrer._DEFAULT_TAGS` `penage/specialists/shared/filter_inferrer.py:16-23` пробует только lowercase теги; case-mix bypass (`<ScRiPt>`) не моделируется. DVWA medium = `str_replace("<script>","")` case-sensitive — PayloadMutator всё равно выдаёт `<img onerror=...>` / `<svg onload=...>`, проходящие prerequisite-фильтр (`payload_mutator.py:123-147`). |
| 3. Gate routing | bypasses `ValidationGate` — `XssSpecialist` вызывает `browser_validator.validate` inline (`xss.py:384-397`); gate validate'ит только финальный `NOTE` от специалиста (no-op в `HttpEvidenceValidator`). Документировано в `gate_routing_specialist_phases.md`. | passes `ValidationGate`: candidate NOTE идёт через gate, но verification — inline (error-signature match + timing delta в `sqli.py`). Gate cascade (`gate.py:86-156`) для SQLi не вызывается (нет `browser_target`, `HttpEvidenceValidator` не имеет SQLi-специфики). | bypasses gate — тот же путь, что #1 reflected low. |
| 4. Applicable EvidenceValidator | `BrowserEvidenceValidator` `penage/validation/browser.py:64` — используется, но его `navigate(url)` идёт на `action.params["url"]`; stored сценарий требует navigate на **render-page** (`/vulnerabilities/xss_s/` GET), а не на inject-endpoint. Нужен либо параметр `browser_navigate_url`, либо двухшаговая post/get последовательность. | missing — нет `SqliEvidenceValidator` / `SqliOracle`. Backend-fingerprint regex и timing delta живут внутри `SqliSpecialist` (`sqli.py:30-67, 441-485`). `HttpEvidenceValidator` `penage/validation/http.py:197` — generic, не классифицирует SQL-ответы. | `BrowserEvidenceValidator` `penage/validation/browser.py:64` — ok, тот же, что #1. |
| 5. Unit test coverage | `tests/unit/test_xss_specialist.py` — 7 тестов, все reflected; stored-специфических нет. | `tests/unit/test_sqli_specialist.py` — 6 тестов (baseline/error/blind branches). | `tests/unit/test_xss_specialist.py` — 7 тестов (reflected low); medium-специфических нет. `FilterInferrer` coverage — `test_filter_inferrer.py`; case-mix не покрыт. |
| 6. Integration test coverage | `tests/integration/test_xss_through_gate.py` — 2 теста (reflected + ablation). Stored — none. | none — нет `test_sqli_through_gate.py`. | `test_xss_through_gate.py` — 2 (reflected low). Medium — none. |
| 7. DVWA prereqs | `/vulnerabilities/xss_s/` POST `txtName`, `mtxMessage` → GET того же URL рендерит guestbook. Auth `security=low` (хардкод `tests/support/dvwa_auth.py:118`). Дополнительно: `view_guestbook` teardown (optional) для reset между runs. | `/vulnerabilities/sqli/?id=<v>&Submit=Submit` GET; `id` — query param. Auth `security=low`. Никакого extra setup. | `/vulnerabilities/xss_r/?name=<v>` GET. Требуется `security=medium` → `dvwa_auth.authenticate` сейчас захардкожен на `low` (`tests/support/dvwa_auth.py:115-122`), нужна параметризация (`security_level: Literal["low","medium","high"] = "low"`). |

## Section 3. Per-scenario detail

### 3.3 Stored XSS (decision: **blocked**)

#### 3.3.1 Vulnerability class + attack mechanics

DVWA target — `POST /vulnerabilities/xss_s/` with form fields `txtName`,
`mtxMessage`, `btnSign=Sign Guestbook` (auth `security=low`). The `mtxMessage`
value is persisted in the guestbook DB table unsanitised. A subsequent
`GET /vulnerabilities/xss_s/` renders the table, including any previously
injected markup, back into the response body. The critical distinction from
reflected XSS is that **inject and trigger are two separate HTTP requests**
against the same URL but with different methods (POST vs GET), and the
trigger observation is not causally tied to the inject request's response.

#### 3.3.2 Why blocked (architectural gap)

* `BrowserEvidenceValidator.validate(...)` issues a single
  `await self._browser.navigate(url)` (`penage/validation/browser.py:143`).
  There is no hook to send an inject-request first and navigate to a
  different trigger-URL afterwards, nor any state-machine for
  "POST → GET → observe".
* `XssSpecialist` phase 4 (payload delivery) and phase 5 (browser
  verification) treat `target_url` as singular (`penage/specialists/vulns/xss.py:380-388`:
  `browser_probe.params["url"] = probe_url`, the same URL used to deliver the
  payload). There is no split between an inject-endpoint and a render-page.
* Stored XSS is therefore not reducible to "the same reflected-XSS pipeline
  with a different URL"; the specialist's pipeline needs a semantic
  extension (two-step inject/trigger), not a config tweak.

#### 3.3.3 Work required (stage 5+)

* **Option A** — extend `BrowserEvidenceValidator` to accept an optional
  inject-request spec: `(inject_url, inject_method, inject_payload_params,
  trigger_url)`. Backward-compat by defaulting `trigger_url = inject_url` and
  skipping the inject step when no inject spec is provided (reflected case).
* **Option B** — dedicated `XssStoredSpecialist` with its own inject-then-
  trigger pipeline; shares `PayloadMutator` + payload library + the existing
  browser oracle. Keeps `XssSpecialist` focused on reflected flows.
* **Open design issues** (for stage 5+, not decisions here):
  * Cookie/session sharing between the `http_tool` (inject POST via httpx)
    and `PlaywrightBrowser` (trigger GET); both must carry the same DVWA
    `PHPSESSID` / `security` cookies for the authenticated guestbook view.
  * State cleanup — DVWA guestbook persists across runs; a cleanup fixture
    (DB-level or UI-driven "Clear Guestbook") is required to keep tests
    idempotent.
  * Concurrent episodes / parallel test runs mutate shared DB state;
    isolation strategy TBD.

#### 3.3.4 Deferred to

**Stage 5+.** Not planned for δ.β. Re-evaluate after SQLi (#4) and
XSS-medium (#5) land and after any stage-5 browser-layer refactors (which
may collapse the gap closure into a larger validator redesign).

### 3.4 SQLi (decision: **go**)

#### 3.4.1 Vulnerability class + attack mechanics

DVWA target — `GET /vulnerabilities/sqli/?id=<PAYLOAD>&Submit=Submit` (auth
`security=low`). Server side renders `SELECT first_name, last_name FROM users
WHERE user_id='$id'` with no escaping; the `id` query parameter is the sole
injection sink and the response includes either the matching row(s) or a raw
MySQL error message.

Three relevant payload families (no full enumeration — the live set lives in
`penage/payloads/sqli.yaml`):

* **Boolean / UNION** — `1' OR '1'='1`, `1' UNION SELECT user, password FROM
  users-- -`. Echo additional rows in the rendered table.
* **Error-based** — `'`, `1' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION()))-- -`.
  Trigger MySQL syntax errors / `XPATH syntax error: '~5.7.28'` style leaks.
* **Time-based blind** — `1' AND SLEEP(2)-- -`. Used when the response body is
  identical for valid vs invalid `id` (not the case for low, but the
  specialist still tries the family if error-based fingerprints fail).

#### 3.4.2 `SqliSpecialist` pipeline walkthrough

Three phases, sequenced inside `SqliSpecialist._run_pipeline`
(`penage/specialists/vulns/sqli.py:217`); reshaped from canonical AWE because
SQL parameter context is not parsed from reflection, so `context_analysis` and
`filter_inference` collapse into the inline payload categories used by
`PayloadMutator.mutate_by_category(...)`.

* **Phase 1 — baseline timing** (`sqli.py:281`, `_measure_baseline`). Sends
  ``baseline_samples=3`` no-injection requests (literal `value="baseline"`),
  records `elapsed_ms`, and stores `median_s` / `max_s` / raw samples. Median
  is the reference for phase 3's blind-timing delta. Returns `None` if fewer
  than 2 samples succeed → pipeline aborts (`sqli.py:232`).
* **Phase 2 — error-based probes** (`sqli.py:302`, `_run_error_phase`).
  Mutator pulls up to `max_error_payloads=4` payloads from category
  `error_trigger`; each is fired against the target. The response body is
  scanned by `_fingerprint_backend` (`sqli.py:632`) for case-insensitive
  substrings keyed on backend (`mysql`: `"you have an error in your sql
  syntax"`, `"mysql server version"`, …; postgres / sqlite / mssql families
  in `_BACKEND_ERROR_SIGNATURES` `sqli.py:30-60`). On a fingerprint hit, up
  to `max_extraction_payloads=3` `error_extract` payloads run against the
  detected backend; their bodies feed `_extract_version` (`sqli.py:643`)
  with backend-specific regexes (`sqli.py:62-67`). A version match makes the
  finding `verified=True` (`sqli.py:395`).
* **Phase 3 — blind timing** (`sqli.py:415`, `_run_blind_phase`). Runs only
  when phase 2 was unverified. Mutator pulls up to `max_blind_payloads=3`
  payloads from `blind_timing` (backend-aware if phase 2 fingerprinted one).
  Each payload fires `probes_per_timing_payload=3` times; samples whose
  `elapsed_s - baseline_s >= timing_threshold_s=5.0` count as hits. ≥
  `timing_hits_required=2` of 3 hits → `verified=True` finding
  (`sqli.py:466`).

**Finding emission.** Findings are stashed in `self._findings` during
`propose_async` (`sqli.py:189`) and converted into a single `CandidateAction`
by `_emit_if_any` (`sqli.py:196-215`). The action is `Action(type=NOTE,
params={"kind": "sqli_finding", "finding": {...}}, tags=["sqli", "verified"
| "unverified", mode])` — there is **no** dedicated `Finding` dataclass; the
finding is the dict shaped by `_run_error_phase` (`sqli.py:401-413`) or
`_run_blind_phase` (`sqli.py:466-484`). Score is 11.0 if verified else 5.0.

#### 3.4.3 Validation oracle

This is the load-bearing departure from XSS-style E2E. Three confirmed facts:

1. **No dedicated SQLi validator exists.** `SqliSpecialist` is the sole
   detection oracle: backend fingerprints (`sqli.py:30-60`), version regexes
   (`sqli.py:62-67`), timing thresholds (`sqli.py:141`, `461`).
2. **`ValidationGate` silently skips the SQLi NOTE.** The chosen
   `Action(type=NOTE, …)` flows through
   `Orchestrator._step_run → validation_gate.validate` (`orchestrator.py:307`).
   The gate's first stage is `HttpEvidenceValidator.validate`, which short-
   circuits at `penage/validation/http.py:278-279` (`if action.type !=
   ActionType.HTTP: return None`). With no `browser_target` flag on the NOTE
   action, the gate cascade returns `None` (`gate.py:115-116`) and
   `ValidationRecorder.record` is not called — **nothing is appended to
   `state.validation_results` for the SQLi NOTE** (`orchestrator.py:310-311`
   guards on `vres is not None`).
3. **There is no `level` field on a SQLi finding.** The truthy signal is
   `finding["verified"]: bool` (set at `sqli.py:395` for error-based,
   `sqli.py:467` for blind-timing). The CandidateAction's `tags` carry
   `"verified"` / `"unverified"` (`sqli.py:200`), and the finding dict has
   `"kind"` ∈ `{"sqli_error_verified", "sqli_error_fingerprint",
   "sqli_blind_timing_verified"}` (`sqli.py:412`, `483`). `State` itself has
   no `findings` field at all (verified via `penage/core/state/__init__.py`).

**Implication for the E2E assertion.** The XSS reflected pattern
(`positive = [r for r in state.validation_results if r["level"] in
{"validated", "evidence"}]`, `test_dvwa_xss_reflected_low.py:80-83`) **does
not transfer** — `state.validation_results` will be empty of SQLi-specific
entries. The finding survives only in (a) the JSONL trace
(`tracer.record_action(NOTE)` serialises `action.params.kind ==
"sqli_finding"` and the full finding dict via `Action.to_dict()`,
`tracer.py:50-58`) and (b) transiently in `CandidateAction.metadata`, which
is not persisted post-policy.

Three viable assertion shapes:

* **(A) Trace-scan, verified-only** (recommended):
  ```python
  events = [json.loads(line) for line in trace_path.read_text().splitlines() if line]
  sqli_actions = [
      e for e in events
      if e["event"] == "action"
      and (e["payload"]["action"].get("params") or {}).get("kind") == "sqli_finding"
  ]
  assert any(
      (e["payload"]["action"]["params"]["finding"] or {}).get("verified") is True
      for e in sqli_actions
  ), f"expected verified sqli_finding in trace; saw {sqli_actions!r}"
  ```
* **(B) Trace-scan, presence-only** — drop the `verified` filter; matches if
  the specialist emitted any candidate (verified or unverified). Looser, but
  catches `sqli_error_fingerprint` (backend identified, no extraction).
* **(C) Tag-scan** — assert `"sqli" in action.tags and "verified" in
  action.tags` over the same event stream. Equivalent to (A); slightly more
  brittle if `tags` ordering changes.

**Recommendation: shape (A)** for the δ.β test. Verified-only matches the
specialist's contract (`finding["verified"]` is the documented oracle in the
class docstring, `sqli.py:120-122`), keeps parity with how the unit tests
assert (`test_sqli_specialist.py:99,147`), and avoids false positives from
drive-by error pages on non-SQLi endpoints. Add a fallback note in the test:
on assertion failure, print the trace tail so the reason is debuggable
without re-running.

#### 3.4.4 Gaps & required work (δ.β)

* **`dvwa_auth.py`** — no changes; `/vulnerabilities/sqli/` works under
  `security=low`, the current hardcoded level (`tests/support/dvwa_auth.py:118`).
* **`build_dvwa_runtime_config`** — reuse as-is. There is **no**
  `vuln_class` / `target_vuln_classes` knob in `RuntimeConfig`
  (`penage/app/config.py:11-92`); `enable_specialists=True` registers all
  vuln specialists unconditionally (`runtime_factory.py:195-247`), and
  per-step arbitration is policy-side. The user prompt should mention SQLi
  to bias the planner toward `/vulnerabilities/sqli/` discovery; this is
  prompt-shaping, not config.
* **New file** — `tests/integration/e2e/test_dvwa_sqli_low.py`. Layout
  mirrors `test_dvwa_xss_reflected_low.py`; assertion uses shape (A).
* **No** changes to `SqliSpecialist`, `ValidationGate`,
  `HttpEvidenceValidator`, payload library, or memory store.
* **Optional baseline test** (`test_dvwa_sqli_no_vuln_baseline.py`) —
  **deferred**. Rationale: SQLi specialist's `_discover_targets` already
  bails out fast on targets with no `id`-like query parameter (returns
  empty list at `sqli.py:533`), so the negative case is structurally
  blocked rather than oracle-blocked. Coverage win is small relative to
  session scope.

#### 3.4.5 Proposed test skeleton

Pseudo-Python (real names verified against `test_dvwa_xss_reflected_low.py`):

```python
async def test_sqli_low_yields_verified_sqli_finding(dvwa_session, tmp_path):
    target_url = f"{dvwa_session.base_url}/vulnerabilities/sqli/?id=1&Submit=Submit"
    cfg = build_dvwa_runtime_config(dvwa_session.base_url, tmp_path / "trace.jsonl",
        target_url=target_url, allowed_host=urlparse(dvwa_session.base_url).hostname,
        experiment_tag="e2e_dvwa_sqli_low")
    bundle = build_runtime(cfg, JsonlTracer(cfg.trace_path, episode_id="e2e-sqli-low"))
    _inject_cookies(bundle, dvwa_session.cookies, host)
    state, _ = await bundle.orchestrator.run_episode(user_prompt=..., state=State(...), ...)
    events = [json.loads(l) for l in cfg.trace_path.read_text().splitlines() if l]
    assert any(e["event"] == "action"
        and (e["payload"]["action"].get("params") or {}).get("kind") == "sqli_finding"
        and (e["payload"]["action"]["params"]["finding"] or {}).get("verified") is True
        for e in events), "expected verified sqli_finding in trace"
```

#### 3.4.6 Decision rationale

**Go.** Specialist exists and is unit-tested; DVWA target has zero auxiliary
setup; gap is purely test-side. **Risk callouts:** (1) first E2E whose
oracle bypasses `ValidationGate` — assertion shape diverges from the XSS
reference; (2) `SqliSpecialist` has never been exercised end-to-end against
DVWA, so flake on payload selection (LLM-mediated `PayloadMutator`) is
plausible — budget retries / `max_steps` accordingly in δ.β.

### 3.5 XSS medium (decision: **go**)

#### 3.5.1 Vulnerability class + attack mechanics

DVWA target — `GET /vulnerabilities/xss_r/?name=<PAYLOAD>`, auth
`security=medium`. Server-side sanitisation is a single
`str_replace("<script>", "", $name)` — case-sensitive removal of the literal
substring `<script>`. Three bypass families:

* **Alternative tags** — `<img src=x onerror=alert(1)>`, `<svg onload=alert(1)>`.
  Do not contain `<script>`; pass the filter untouched. **This is the path
  penage takes** (see 3.5.2).
* **Case-mix** — `<ScRiPt>alert(1)</ScRiPt>`. Bypasses DVWA medium (case-
  sensitive `str_replace`) but is not generated by `FilterInferrer` (lowercase
  probes only, see 3.5.4).
* **Nested** — `<scr<script>ipt>alert(1)</script>`. After one pass of
  `str_replace` collapses to `<script>…</script>`; brittle (depends on
  single-pass removal) and not modelled in the payload library.

#### 3.5.2 Specialist pipeline walkthrough

Same 5-phase pipeline as reflected-low (`XssSpecialist._run_pipeline`
`penage/specialists/vulns/xss.py:193-311`); only phase 3+4 behave differently
under medium:

* **Phase 3 — filter inference** (`xss.py:247-262`). `FilterInferrer`
  (`penage/specialists/shared/filter_inferrer.py:55`) fires wrapped probes for
  each tag/event/char. Against DVWA medium the `<script>` probe comes back
  with the tag stripped → `_classify` (`filter_inferrer.py:158`) records it
  under `filter_model.blocked_tags`, while `<img>` / `<svg>` / event probes
  land in `allowed_tags` / `allowed_events`.
* **Phase 4 — payload mutation** (`xss.py:268-291`, `PayloadMutator.mutate`
  at `xss.py:284`). Prerequisite-gating (`payload_mutator._select_entries`
  `payload_mutator.py:120`, tag-subset check `payload_mutator.py:343-350`)
  drops any library entry whose `prerequisites.tags` is not a subset of
  `filter_model.allowed_tags`. Entries keyed on `<img>` / `<svg>` survive;
  `<script>`-keyed entries are filtered out. Net result: payloads like
  `<img src=x onerror=alert(1)>` reach phase 5.
* **Phases 1/2/5** — identical to reflected-low; phase 5 reuses the inline
  browser path (`xss.py:313-458`, same gate-bypass caveat as #1, documented
  in `gate_routing_specialist_phases.md`).

**Known gap (not a blocker for #5).** `FilterInferrer._DEFAULT_TAGS` is
lowercase only (`filter_inferrer.py:16-23`) and `_classify` compares
observed-vs-payload byte-exactly (`filter_inferrer.py:178`), so case-mix
bypass (`<ScRiPt>`) is never inferred or generated. Medium is still handled
via alt-tag routing. **DVWA high** — `preg_replace('/<(.*)s(.*)c(.*)r...`
— also falls to alt-tag bypass, but case-mix remains un-modelled; high is
out of scope for δ.β.

#### 3.5.3 Validation oracle

`BrowserEvidenceValidator` (`penage/validation/browser.py:64`) — byte-
identical to reflected low. Gate cascade runs; specialist's phase-5 inline
validator writes to `state.validation_results` with `level` ∈
`{"validated", "evidence"}` (docstring contract at `browser.py:96-100`).

**E2E assertion form** mirrors `test_dvwa_xss_reflected_low.py:80-87` —
`state.validation_results` is a **list of dicts**, keyed with
`r.get("level")`:

```python
positive = [r for r in state.validation_results
            if str(r.get("level")) in {"validated", "evidence"}]
assert positive
```

No trace-scan needed (contrast with SQLi #4).

#### 3.5.4 Gaps & required work (δ.β)

* **Required: `tests/support/dvwa_auth.py:62`** — add
  `security_level: str = "low"` kwarg to `authenticate(...)`. The default
  preserves back-compat for every existing call site (reflected-low E2E,
  any future low-security scenario). At `dvwa_auth.py:118`, replace literal
  `"security": "low"` with `"security": security_level`. Optional
  validation (`assert security_level in {"impossible","low","medium","high"}`)
  is nice-to-have but not required — DVWA itself ignores unknown values.
* **`tests/support/e2e_config.py::build_dvwa_runtime_config(...)` — do not
  touch.** Rationale: security level is a property of the authenticated
  session (fixture input to `dvwa_auth.authenticate`), not of
  `RuntimeConfig`. The helper stays minimal; the new test body calls
  `authenticate(..., security_level="medium")` directly. Keeps the helper's
  single responsibility intact.
* **Required unit coverage** — `tests/unit/support/test_dvwa_auth.py`:
  +1-2 cases. (a) default call still posts `security=low` to
  `/security.php`; (b) `security_level="medium"` posts `security=medium`.
  httpx mocking pattern already exists for login-flow tests in that file.
* **Required new E2E** — `tests/integration/e2e/test_dvwa_xss_reflected_medium.py`.
  Copy of `test_dvwa_xss_reflected_low.py` with:
  `authenticate(..., security_level="medium")` in the fixture/setup (either
  a new `dvwa_session_medium` fixture or an inline re-auth at the top of
  the test), `target_url` still `/vulnerabilities/xss_r/?name=probe` (same
  endpoint), assertion unchanged.
* **NOT required** — no changes to `XssSpecialist`, `FilterInferrer`,
  `PayloadMutator`, `BrowserEvidenceValidator`, `ValidationGate`,
  `RuntimeConfig`, or the payload library.

#### 3.5.5 Proposed test skeleton

```python
async def test_xss_reflected_medium_yields_validated_or_evidence(
    dvwa_session_medium: DvwaSession, tmp_path: Path
) -> None:
    target_url = f"{dvwa_session_medium.base_url}/vulnerabilities/xss_r/?name=probe"
    cfg = build_dvwa_runtime_config(dvwa_session_medium.base_url, tmp_path/"trace.jsonl",
        target_url=target_url, allowed_host=urlparse(dvwa_session_medium.base_url).hostname,
        experiment_tag="e2e_dvwa_xss_reflected_medium")
    bundle = build_runtime(cfg, JsonlTracer(cfg.trace_path, episode_id="e2e-xss-medium"))
    _inject_cookies(bundle, dvwa_session_medium.cookies, ...)
    state, _ = await bundle.orchestrator.run_episode(user_prompt=..., state=State(...), ...)
    assert [r for r in state.validation_results
            if str(r.get("level")) in {"validated", "evidence"}]
```

#### 3.5.6 Decision rationale

**Go** with a single helper tweak (`dvwa_auth.authenticate` kwarg). Risk
**low**: full infrastructure reuse from reflected-low, only uncertainty is
`FilterInferrer` inference quality on DVWA medium — if that flakes the
mitigation is a debug log, not a redesign (alt-tag bypass is deterministic
once `<script>` lands in `blocked_tags`).

## Section 4. Integrated plan for δ.β

#### 4.1 Scope

Two scenarios go into δ.β: **#5 XSS medium** and **#4 SQLi**. **#3 Stored
XSS** is deferred to stage 5+ (see 3.3.4). No other work in scope.

#### 4.2 Proposed ordering

Split into two micro-sessions:

* **δ.β.1 — XSS medium first.** Low risk: reuses the reflected-low E2E
  infrastructure end to end; the only production-adjacent change is a
  one-line kwarg on `tests/support/dvwa_auth.py::authenticate`. Estimated
  ~30-60 min in a Claude Code session.
* **δ.β.2 — SQLi second.** Higher novelty: first E2E whose oracle bypasses
  `ValidationGate`, new `state.validation_results`-free assertion paradigm
  (trace-scan JSONL for `kind == "sqli_finding"` + `verified is True`, see
  3.4.3 shape (A)), first end-to-end exercise of `SqliSpecialist` against
  DVWA. Estimated ~60-90 min.

Rationale: one or two confident E2E tests beat three shaky ones. Landing
XSS medium first banks an incremental win even if SQLi uncovers planner/
payload-selection surprises that bleed across session boundaries.

**Single-session alternative** — XSS medium + SQLi in one δ.β (~1.5-2 h
total). Risk: stream timeout truncates scope and SQLi spills into a re-
session with partial context. **Recommendation: split** into δ.β.1 and
δ.β.2.

#### 4.3 Aggregated work items

**Helper / production-adjacent (δ.β.1, cross-ref 3.5.4):**

* `tests/support/dvwa_auth.py:62` — add `security_level: str = "low"` kwarg
  to `authenticate(...)`. Default preserves back-compat for every existing
  call site.
* `tests/support/dvwa_auth.py:118` — replace the literal `"security": "low"`
  form value with `"security": security_level`.
* `tests/support/e2e_config.py::build_dvwa_runtime_config` — **no change**.
  Rationale: security level belongs to the auth fixture, not to
  `RuntimeConfig` (which has no `vuln_class` / `target_vuln_classes` knob
  anyway, cf. 3.4.4).
* `tests/unit/support/test_dvwa_auth.py` — +1-2 cases: (a) default call
  still posts `security=low`; (b) `security_level="medium"` posts
  `security=medium`.

**New E2E test (δ.β.1, cross-ref 3.5.4/3.5.5):**

* `tests/integration/e2e/test_dvwa_xss_reflected_medium.py`. Copy the
  reflected-low layout; call `authenticate(..., security_level="medium")`
  in the fixture; assert on `state.validation_results` as a **list of
  dicts** via `r.get("level") in {"validated", "evidence"}` (not attribute
  access — confirmed in 3.5.3).

**New E2E test (δ.β.2, cross-ref 3.4.4/3.4.5):**

* `tests/integration/e2e/test_dvwa_sqli_low.py`. `target_url` =
  `".../vulnerabilities/sqli/?id=1&Submit=Submit"`; user prompt bias
  (e.g. `"find SQL injection on {target}"`); assertion = trace-scan JSONL
  for an `action` event whose `payload.action.params.kind == "sqli_finding"`
  and `params.finding.verified is True` (3.4.3 shape (A)).
* **Optional baseline** (`test_dvwa_sqli_no_vuln_baseline.py`) — **defer**,
  not in δ.β scope. Rationale: `SqliSpecialist._discover_targets` bails on
  targets with no `id`-like query param (see 3.4.4), so the negative case
  is structurally blocked rather than oracle-blocked; coverage win is small
  and the gate-regression angle (the XSS baseline's selling point)
  bypasses the gate for SQLi anyway. Re-evaluate in 4.7 docs close.

**Zero production-code changes.** Not `XssSpecialist`, `SqliSpecialist`,
`ValidationGate`, `BrowserEvidenceValidator`, `HttpEvidenceValidator`,
`RuntimeConfig`, `PayloadMutator`, or the payload library.

#### 4.4 Expected test count delta

* `pytest -q` default selection: **713 passed → 714-715 passed** (+1-2
  unit tests for `dvwa_auth` kwarg). Baseline `1 skipped, 11 deselected`
  unchanged.
* `-m e2e_dvwa` selection: **+2 new E2E tests**
  (`test_dvwa_xss_reflected_medium.py`, `test_dvwa_sqli_low.py`), both
  deselected by default.
* No newly-skipped tests.

#### 4.5 Estimated session length

* **δ.β.1 (XSS medium)** — short-to-medium, ~30-60 min Claude Code. Risks:
  none material; full pattern reuse from reflected-low.
* **δ.β.2 (SQLi)** — medium, ~60-90 min. Primary risk: `SqliSpecialist`
  may not be selected by the planner/policy against DVWA despite a
  biasing `target_url` + user prompt (arbitration is policy-side, not
  vuln-class-routed, cf. Section 5 Q1). Mitigation: verify via trace
  tail on first failure; adjust `user_prompt` wording or add
  specialist-name hint if needed.

#### 4.6 Open questions forwarded to δ.β

* **δ.β.2**: is `user_prompt="find SQL injection on {target}"` enough
  planner bias, or does the prompt need to mention the URL / the
  specialist by name? Empirical — decide from the first E2E trace.
* **δ.β.2**: run-time budget — current XSS default is `max_steps=12` /
  `max_http_requests=60`; `SqliSpecialist` runs baseline (3 samples) +
  up to 4 error probes (+3 extractions on hit) + up to 3 blind payloads
  × 3 probes each at ~5s threshold. Pre-emptive bump: **`max_steps=16`,
  `max_http_requests=80`** for the SQLi test.
* **δ.β.1**: is `FilterInferrer` behaviour on DVWA medium observable in
  the trace? If inference mimics a wrong filter model the trace gives
  debug surface; if phase 4 picks `<img>` / `<svg>` cleanly, skip.
* **Forwarded to 4.7 docs close** (not blockers for δ.β):
  * Type of `state.validation_results` — `list[dict]` vs
    `list[ValidationResult]` — and whether the list-of-dicts convention
    should be codified.
  * `FilterInferrer` case-mix blindness (DVWA high bypass) — future
    specialist extension or acceptable gap.
  * AWE 5-phase qualifier for SQLi (baseline/error/blind vs canonical
    canary/context/filter/mutate/verify), cf. `inv #3`.



## Section 5. Open questions

- **Q:** Как orchestrator выбирает specialist под конкретный vuln-class? Hard-coded dispatch или auto? **Status:** answered. **Tentative answer:** hard-coded — `build_specialists` в `penage/app/runtime_factory.py:165-250` всегда регистрирует все vuln-специалисты при `enable_specialists=True`. Выбор одного действия из N candidate-proposals делает policy/coordinator через `CandidatePool.finalize` + один `actions_per_step`. Per-vuln routing отсутствует.
- **Q:** Является ли `enable_specialists=True` multi-specialist режимом или single-specialist с конфиг-выбором? **Status:** answered. **Tentative answer:** multi-specialist — `SpecialistProposalRunner.run_mixed` (`penage/specialists/manager.py:37`) параллельно запускает `propose_async` всех зарегистрированных specialists каждый outer-step; арбитраж — на policy-слое.
- **Q:** Что происходит, если validation oracle отсутствует для текущего vuln class — silent skip или hard failure? **Status:** answered. **Tentative answer:** silent. Gate cascade (`validation/gate.py:94-116`) возвращает `None` от `HttpEvidenceValidator`, при отсутствии `browser_target` не вызывает browser; результат — candidate action пишется в `state.validation_results` со `level != "validated"`, ассёрт в E2E-тесте (см. `test_dvwa_xss_reflected_low.py:82-87`) потребует хотя бы `level ∈ {validated, evidence}`. Для SQLi (#4) это значит: если специалист не родил finding — тест провалится с пустым `positive`.
- **Q:** Может ли текущий payload generator XSS-специалиста делать filter-bypass (case-mix, nested tags)? **Status:** needs-δ.β-investigation. **Tentative answer:** частично. `PayloadMutator` умеет выбирать payloads по `FilterModel.allowed_tags/events` (`payload_mutator.py:123-147`) — т.е. если `<script>` заблокирован, но `<img>` + `onerror` разрешены, mutator выдаст `<img src=x onerror=alert(1)>`. Этого достаточно для DVWA medium (`str_replace("<script>","")`). Case-mix (`<ScRiPt>`) и nested-tag bypass (`<scr<script>ipt>`) — **не моделируются**: `FilterInferrer._DEFAULT_TAGS` только lowercase (`filter_inferrer.py:16-23`), prerequisites matching в `payload_mutator._select_entries` работает по strip-lowered тегам.
- **Q:** Может ли `BrowserEvidenceValidator` верифицировать stored XSS, когда injection-URL и trigger-URL совпадают, но HTTP-flow двухшаговый (POST → GET)? **Status:** needs-δ.β-investigation. **Tentative answer:** неочевидно. `BrowserEvidenceValidator.validate` делает **один** `navigate(action.params["url"])` (`validation/browser.py:114+`). Если `XssSpecialist` эмитит browser-probe с `url=/xss_s/` после POST-инъекции через `http_tool`, куки делятся между httpx и Playwright только если `PlaywrightBrowser` читает тот же cookie jar — требует проверки в δ.α.2.

## Section 6. Appendix — file pointer list

- `penage/specialists/vulns/xss.py:81` — `XssSpecialist`, read fully.
- `penage/specialists/vulns/xss.py:131-168` — `propose_async` + targets loop, read fully.
- `penage/specialists/vulns/xss.py:313-458` — phase 5 inline browser verification, read fully.
- `penage/specialists/vulns/xss.py:460-498` — `_discover_targets` (forms + last_http_url query), read fully.
- `penage/specialists/vulns/sqli.py:104` — `SqliSpecialist`, read fully.
- `penage/specialists/vulns/sqli.py:217-279` — 3-phase pipeline (baseline / error / blind), read fully.
- `penage/specialists/vulns/sqli.py:302-413` — error-based fingerprint + extraction, read fully.
- `penage/specialists/vulns/sqli.py:415-486` — blind-timing branch, read fully.
- `penage/specialists/shared/filter_inferrer.py:16-110` — `_DEFAULT_TAGS/EVENTS/CHARS` + probes, read partially (skipped: `_classify` details past line 200).
- `penage/specialists/shared/payload_mutator.py:31-215` — `PayloadMutator.mutate` + `mutate_by_category`, grepped only (verified prerequisite-matching path).
- `penage/validation/gate.py:49-156` — `ValidationGate` cascade, read fully.
- `penage/validation/http.py:197-359` — `HttpEvidenceValidator`, read partially (skipped: helper predicates lines 100-195).
- `penage/validation/browser.py:64-119` — `BrowserEvidenceValidator` contract, read partially.
- `penage/specialists/manager.py:1-38` — `SpecialistManager` + proposal runner wiring, read fully.
- `penage/app/runtime_factory.py:165-250` — `build_specialists`, read fully (all vuln specialists always registered).
- `tests/support/dvwa_auth.py:62-124` — `authenticate(...)` hardcodes `security=low`, read fully.
- `tests/integration/e2e/test_dvwa_xss_reflected_low.py:1-99` — reference E2E layout, read fully.
- `tests/integration/test_xss_through_gate.py` — grepped only (2 tests, reflected only).
- `penage/payloads/xss.yaml` (head) — prerequisite-gated payload library entries (html_body script/img/svg), grepped only.
- `docs/design/gate_routing_specialist_phases.md` — read fully; инвариант: phase-5 inline validation оставлен до Stage 5.0.
