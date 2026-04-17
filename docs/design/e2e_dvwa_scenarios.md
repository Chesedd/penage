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

<!-- filled in δ.α.2 -->

## Section 4. Integrated plan for δ.β

<!-- filled in δ.α.2 -->

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
