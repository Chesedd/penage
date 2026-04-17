# Gate routing для specialist phases — design note

**Статус:** deferred to Stage 5 (benchmarks + protocol evolution).
**Этап:** 4.1.b.iii.γ (investigation).
**Связанные инварианты:** CLAUDE.md №3 (AWE 5-phase), №4 (единый validation-путь),
№10 (agents as proxies, not logic).

## Проблема

Инвариант №4 требует, чтобы все находки проходили через одну точку валидации —
`ValidationGate`. Gate-cascade в `penage/validation/gate.py:86-156` уже поддерживает
browser-ветку (`browser_target=True` → `BrowserEvidenceValidator`), появившуюся в
4.1.b.ii.

Однако `XssSpecialist.phase 5` в `penage/specialists/vulns/xss.py:313-458` всё ещё
выполняет browser-валидацию **inline**:

- специалист сам строит `browser_probe` (строки 371-381),
- сам вызывает `self.browser_validator.validate(action=..., obs=..., state=...)`
  (строки 384-388),
- сам пишет результат в `state.last_validation` через
  `self.validation_recorder.record(...)` (строки 393-397),
- сам ассемблирует `finding` на основе `vres.level` (строки 399-454).

Это означает, что **два пути validation** фактически сосуществуют:

1. Gate-cascade (для действий, прошедших через `Orchestrator._run_action`).
2. Specialist-inline (для phase-5 probes XssSpecialist'а).

Оба пути в итоге вызывают один и тот же `BrowserEvidenceValidator` instance
(инжектируется в `runtime_factory.build_orchestrator` и в gate, и в
`XssSpecialist`; см. `penage/app/runtime_factory.py:180-187, 304-326`), так что
**классификация** (validated/evidence/None) идентична. Но архитектурно существует
второй caller, и любое будущее обогащение gate-cascade (например, agent-mode
escalation для browser findings, telemetry, rate-limiting, дополнительные stages)
обойдёт phase 5.

## Текущий контракт Specialist

Source: `penage/specialists/base.py:17-29`.

```python
@runtime_checkable
class AsyncSpecialist(Protocol):
    name: str
    async def propose_async(
        self, state: State, *, config: SpecialistConfig
    ) -> List[CandidateAction]:
        ...
```

**Семантика в orchestrator-loop** (`penage/core/orchestrator.py:172-176`,
`penage/specialists/proposal_runner.py:52-78`):

1. На каждой outer-step итерации orchestrator вызывает
   `await specialists.propose_all_async(st)` **ровно один раз**.
2. `SpecialistProposalRunner.run_mixed` ждёт все `propose_async` корутины
   (параллельно через `asyncio.gather`), собирает список `CandidateAction`.
3. Coordinator + policy выбирают **одно** действие из LLM-предложений и
   specialist-кандидатов (`actions_per_step=1` по умолчанию).
4. Выбранное действие идёт через `_run_action → tools.run → state_updater →
   validation_gate.validate → validation_recorder.record`. Это и есть точка, где
   пишется `state.last_validation`.

**Ключевая особенность:** `propose_async` — это **one-shot coroutine**. У специалиста
нет способа "приостановиться после emit'а действия и продолжиться после того,
как orchestrator выполнил dispatch + gate". Единственный канал возврата —
`return List[CandidateAction]`.

Вторая важная особенность: phases 1-4 XssSpecialist'а **не эмитят** действия в
orchestrator. Они вызывают `_BudgetedHttpTool.run(probe_action)` **напрямую**
(`penage/specialists/vulns/xss.py:213, 257, 338`). Это значит, что ~30 probe
HTTP-запросов специалиста никогда не проходят через gate. Только финальный
`ActionType.NOTE` с уже-ассемблированным finding'ом проходит через orchestrator
dispatch — и gate не валидирует NOTE-действия (нет `browser_target`, кроме того
`HttpEvidenceValidator` не обрабатывает NOTE).

Phase 5 выполняет внутренний цикл по N сгенерированным payload'ам. Для каждого
payload: HTTP probe → (если reflected) browser validate → (если validated)
short-circuit и return finding.

## Что мешает split'у phase 5 через gate

Branch A предлагает: phase 5 эмитит probe-action с
`params["browser_target"]=True, params["browser_payload"]=<payload>`, orchestrator
dispatch'ит, gate validates, `state.last_validation` наполняется, специалист
читает результат и ассемблирует finding.

Блокеры:

1. **One-shot контракт propose_async (base.py:28).** После `return` специалист
   не может продолжиться в том же step. Следующий шанс — следующая outer-step.
2. **Один action per step (orchestrator.py:225).** `batch = chosen_actions[:
   max(1, actions_per_step)]`, по умолчанию `actions_per_step=1`. Значит для N
   payload'ов нужно N orchestrator-ticks; внутри каждого тика специалист может
   тестировать максимум один payload.
3. **Policy-арбитраж (orchestrator.py:198-218).** Выбранный специалистом
   `CandidateAction` конкурирует с LLM-actions и кандидатами других
   специалистов. Policy может выбрать не-XSS действие. Специалист теряет
   контроль над порядком итерации payload'ов.
4. **Потеря специалистной state-машины.** Текущие phases 1-4 производят
   `filter_model`, `primary_ctx`, `payloads[]`, `channel`, `target`. Эти данные
   сейчас живут как локальные переменные внутри `_run_pipeline`. При переходе
   на multi-tick pattern они должны persist'иться между `propose_async`
   вызовами — значит надо добавить внутренний state-machine (`_pending_targets`,
   `_pending_payloads[target]`, `_awaiting_validation[probe_fingerprint]`).
5. **Отсутствие механизма "read-back" валидации для проактивного специалиста.**
   `state.last_validation` — это **последняя** валидация, и она пишется **любым**
   dispatched action (не только XSS probe). Специалисту нужно идентифицировать
   "это моё?" — либо по action-fingerprint (нестабильно при policy-нормализации
   action'а), либо через дополнительное поле в `ValidationResult` / `state`,
   либо через обогащение schema `last_validation` owner-меткой.
6. **Сохранение evidence-проверки до browser-эскалации.** Phase 5 отбрасывает
   payload'ы без HTTP-reflection **до** похода в browser (xss.py:346-362,
   дешёвый short-circuit). Gate-path сейчас безусловно вызывает
   `browser_validator.validate` при `browser_target=True`. Миграция должна
   сохранить двух-уровневую логику без дополнительных round-trips в chromium.

## Необходимые изменения в Specialist Protocol

Три варианта, в порядке возрастающей инвазивности.

### Вариант 1. Явная continuation через "resume" в state

- Добавить `SpecialistContext` (per-specialist dict в `State.specialist`) с
  `pending_probes`, `awaiting_validation`, `phase_cursor`.
- `propose_async` читает контекст, решает: "первый вызов → run phases 1-4 и
  эмитить первый probe"; "probe отправлен, результата нет → noop"; "в
  `state.last_validation` пришёл ответ на мой probe → ассемблировать finding
  или следующий payload".
- Owner-метка в probe: `params["originator"]="xss"` + matching check в
  `last_validation.evidence["originator"]` (gate/recorder прокидывают).

**Плюсы:** без изменения сигнатуры Protocol.
**Минусы:** ~большой объём repeated boilerplate в каждом vuln-специалисте;
distributed state-machine трудно тестировать; per-target backpressure между
specialist'ами не решается.

### Вариант 2. Async-generator Protocol

```python
class AsyncSpecialist(Protocol):
    async def propose_async(
        self, state: State, *, config: SpecialistConfig,
    ) -> AsyncIterator[SpecialistYield]: ...
```

где `SpecialistYield` = `Emit(CandidateAction)` | `WaitForValidation` |
`Finding(dict)` | `Done`. Orchestrator advance'ит генератор: после dispatch +
gate кладёт `validation` обратно через `.asend(result)`.

**Плюсы:** естественно выражает intra-step continuation; убирает distributed
state-machine; тесты специалистов становятся табличными (generator-driven).
**Минусы:** ломает контракт `propose_async`, вся wiring orchestrator'а +
`SpecialistProposalRunner` + parallel-specialists пересобирается. Parallelism
между specialist'ами (сейчас `asyncio.gather`) становится неочевидным — два
генератора не могут асинхронно "ждать валидацию" для одного slot'а
`actions_per_step`.

### Вариант 3. Специалист как "action-loop driver", orchestrator как worker

Специалист запрашивает у orchestrator'а блокирующе: `await
orchestrator.dispatch_and_validate(probe)` — orchestrator внутри prop'ом
вызывает coordinator (с `bypass_policy=True`), gate, recorder, возвращает
`ValidationResult`.

**Плюсы:** явная синхронная семантика внутри специалиста, минимальные изменения
специалистов (заменяют `http_tool.run` + inline validate на один
`orchestrator.dispatch_and_validate`).
**Минусы:** policy / coordinator bypass; orchestrator становится re-entrant;
per-step budget учёт и tracing (`record_action(... agent="coordinator")`)
теряют смысл — действие driven специалистом, не coordinator'ом. Нарушает
инвариант №10 (agents как thin proxies) — orchestrator начинает исполнять
логику специалиста.

### Рекомендация

Вариант 2 (async-generator Protocol) семантически чище и лучше соответствует
AWE 5-phase pipeline (каждая фаза — yield-point для external observation).
Вариант 1 — компромисс, если Stage 5 давит по времени и переписывать
orchestrator rewiring нельзя.

## Estimated scope

**Файлы, которые затронет миграция (для варианта 2):**

- `penage/specialists/base.py` — новый `AsyncIterator` контракт + union типов
  yield'ов.
- `penage/specialists/proposal_runner.py` — пересборка `run_mixed`; parallelism
  политика пересматривается.
- `penage/core/orchestrator.py` — цикл `_run_step` становится двухфазным
  (`advance specialists → dispatch → feed validation back`).
- `penage/specialists/vulns/xss.py` — phase 5 переписан под generator.
- `penage/specialists/vulns/sqli.py`, `ssti.py`, `lfi.py`, `xxe.py`, `idor.py`
  — потенциально (если они тоже в будущем захотят gate-routing); сейчас они
  не делают inline validation, так что миграция для них — чистая
  инфраструктурная.
- `penage/specialists/research_llm.py`, `curl_recon.py`, `navigator.py`,
  `research.py`, `sandbox_smoke.py`, `login_workflow.py`,
  `auth_session_confusion.py` — должны продолжать работать; выбор: либо
  общий Protocol с trivial generator (`yield Done`), либо сохранить
  `AsyncSpecialist` рядом со `GeneratorSpecialist`.

**Тесты, которые потребуют изменений:**

- `tests/unit/test_xss_specialist.py` (5 тестов) — все переписываются на
  generator-driven sequence.
- `tests/integration/test_xss_through_gate.py` (2 теста) — становятся
  orchestrator-driven e2e.
- `tests/unit/specialists/test_proposal_runner.py` и любые mock-specialists в
  тестах — каждый mock превращается в generator.

**Конфиг / CLI:** изменений не требуется (`browser_verification` bool уже
существует в `RuntimeConfig` с 4.1.b.ii).

**Оценка размера:** 4-6 сессий (protocol rewrite → xss migration → other
specialists glue → тестовый пакет → bench smoke).

## Предложенная траектория

1. **Stage 4.7 docs close (заключение Stage 4):** в CLAUDE.md зафиксировать
   qualifier к инварианту №4: *"specialists могут делать internal validation
   через инжектированный `BrowserEvidenceValidator` до тех пор, пока
   `Specialist` Protocol не поддерживает continuation. Оба caller'а обязаны
   делить один instance `BrowserEvidenceValidator` (см. `runtime_factory`),
   чтобы classification была идентичной. Рефакторинг — в Stage 5."*
2. **Stage 5.0 (preparation phase для benchmarks):** реализовать Вариант 2
   (async-generator Protocol). Это должно произойти **до** benchmark runs,
   так как XBOW / DVWA измерения будут "замораживать" текущий contract.
3. **Stage 5.1+ (benchmarks):** запустить с новой архитектурой; убедиться, что
   ablation `--no-browser-verification` даёт ожидаемую дельту (evidence
   findings только HTTP-reflection).

## Открытые вопросы (для Stage 5.0)

- Как outlined'ed specialist'ы (навигатор, curl-recon), которые НЕ делают
  validation, сосуществуют с generator-based vuln-специалистами? Union-тип
  или два раздельных Protocol'а?
- Как policy/coordinator видят yield'ящий generator: выбирают ли один slot
  "из всех" или у каждого активного специалиста свой slot?
- `state.last_validation` vs `state.specialist[name].last_validation` — если
  параллельно несколько specialist'ов ждут gate, одно общее поле создаёт
  race. Лучше namespace'ить per-specialist.
- `run_episode`-level teardown: generator может быть в "suspended" состоянии
  на `max_steps`-границе. `asyncio.aclose()` всех активных генераторов — в
  `try/finally` rune episode.
