# Roadmap: эволюция penage в гибрид AWE + MAPTA + CAI

Этот документ — единственный источник истины по плану развития. Каждый этап закрывается строго по «условиям выхода». Не переходить к следующему, пока текущий не закрыт.

Маркеры статуса: ⬜ не начат, 🚧 в работе, ✅ закрыт.

---

Current stage: 2 — AWE-style vulnerability specialists

## Этап 0 — Текущее состояние (baseline)

**Что есть:**

- Слоистая архитектура `app / core / tools / sandbox / llm / specialists / policy / macros / validation`.
- JSONL-трассировка + structured summary JSON.
- Режимы `safe-http` и `sandboxed` (Docker).
- Специалисты уровня recon + auth (`LoginWorkflow`, `Navigator`, `Research`, `ResearchLLM`, `AuthSessionConfusion`, `CurlRecon`, `SandboxSmoke`).
- `policy/gctr_lite` — эвристическое ранжирование, **не game theory** (будет переименовано или поглощено на этапе 4).
- Ollama как единственный LLM-бэкенд.
- `State.facts` как широкий dict.

**Чего нет:** эксплуатационных специалистов по классам уязвимостей, браузерной верификации, persistent memory, настоящих multi-agent ролей, attack graph, Nash equilibrium, digest injection, бенчмарк-раннеров, LLM-бэкендов кроме Ollama.

---

## Этап 1 — Наведение порядка в основании

**Статус:** ✅  
**Цель:** типизировать состояние, добавить реальный cost accounting, подключить frontier LLM-бэкенды, завести persistent memory.  
**Условия входа:** ничего (стартовый этап).  

**Условия выхода:**

1. `State.facts` используется только для свободных notes; все структурные данные — в типизированных dataclass’ах.
2. Доступны минимум три LLM-бэкенда: `FakeLLM`, `OllamaLLM`, `AnthropicLLM`. (OpenAI — опционально.)
3. Summary содержит секцию `resource_stats` с полями: `input_tokens`, `output_tokens`, `cached_tokens`, `reasoning_tokens`, `tool_calls`, `wall_clock_s`, `api_cost_usd`.
4. Реализован early-stop при превышении любого из порогов: 40 tool calls, $0.30 API cost, 300 s wall-clock (все три настраиваемые через CLI).
5. Появился модуль `penage/memory/` с SQLite-бэкендом, две таблицы: `scan_state`, `cross_target`.
6. Все тесты зелёные, покрытие новых модулей ≥ 80%.

### Задачи

**1.1 — Типизированное состояние.**  
Файлы: `penage/core/state.py` → `penage/core/state/` (пакет).  
Разнести:

- `ObservedContext` — где и как параметр отражается (кавычки, тег, атрибут, JS-строка, URL).
- `FilterModel` — какие теги, события, спец-символы, кодировки режутся/нормализуются.
- `ParameterMap` — параметры по endpoint’ам с метаданными типа и способа передачи.
- `PayloadHistory` — `payload → outcome` для дедупликации.
- `AuthState` — cookies, tokens, текущая роль.
- `PivotMap` — обнаруженные pivot-точки.
- `RunBudget` — счётчики ресурсов и лимиты.

`State.facts` остаётся только под свободные строковые заметки. Миграция: каждое обращение `state.facts["..."]` заменить на доступ через соответствующее типизированное поле. Это чистый рефакторинг, поведение не меняется — существующие тесты должны пройти без правок.

**1.2 — LLM-бэкенды.**  
Файлы: `penage/llm/anthropic.py` (новый), при желании `penage/llm/openai.py`.  
Интерфейс `LLMClient` из `penage/llm/base.py` — новые клиенты его реализуют. Важно: Anthropic Messages API несёт system prompt отдельным полем, именно туда на этапе 4 будет инжектиться digest. Возвращаемый объект должен нести: текст, input/output/cached токены, optional reasoning-токены, api-cost.

**1.3 — Cost accounting.**  
Файлы: `penage/core/usage.py` (новый), `penage/app/summary.py`, `penage/llm/pricing.py`.  
`UsageTracker` — thread-safe, агрегирует по ролям (на этапе 3 будет отдельно для Coordinator / Sandbox / Validation; пока — одна роль «planner»). Поля — как в условии выхода 3. Прайс-таблица моделей — в `pricing.py`, с возможностью переопределения через env.

**1.4 — Early-stop.**  
Файлы: `penage/core/orchestrator.py`.  
Перед каждым новым шагом — сверка с `RunBudget`. Превышение любого порога → graceful остановка, запись `summary`-события с причиной, выход. Новые CLI-флаги: `--max-tool-calls`, `--max-cost-usd`, `--max-wallclock-s` с дефолтами из условия выхода 4.

**1.5 — Persistent memory.**  
Файлы: `penage/memory/__init__.py`, `penage/memory/sqlite_store.py`, `penage/memory/schema.sql`.  
Таблицы:

- `scan_state(episode_id, key, value, ts)` — короткая память эпизода (payloads tried, filters inferred, progress markers).
- `cross_target(fingerprint, category, pattern, success_rate, last_seen)` — долгая память между эпизодами. `fingerprint` — хэш stack-детекции (framework, WAF).

API: `MemoryStore.get(key) / set(key, value) / record_outcome(category, pattern, success: bool) / best_patterns(category, limit)`.

**1.6 — Документация.**  
Обновить `docs/architecture.md` (секции Layer map, State model, Memory, LLM backends). Обновить `README.md` (команды, новые CLI-флаги).

### Замечания по дизайну

- Миграция State — самая рискованная часть этапа. Делать в отдельной ветке, гонять полный `pytest` после каждого перенесённого поля.
- Anthropic API отдельно считает `cache_creation_input_tokens` и `cache_read_input_tokens` — оба нужно класть в `cached_tokens` и различать в подробном логе usage.
- SQLite-файл — `runs/memory.db` по умолчанию; путь настраивается через `--memory-path`; добавить в `.gitignore`.
- Прайс-таблица должна быть легко обновляемой: модели и цены меняются регулярно, не хардкодить в коде бизнес-логики.

---

## Этап 2 — Специалисты AWE по классам уязвимостей

**Статус:** ⬜  
**Цель:** заменить обобщённого `ResearchLLMSpecialist` набором эксплуатационных специалистов с пятифазными пайплайнами AWE-стиля, добавить браузерную верификацию.  
**Условия входа:** этап 1 закрыт.  

**Условия выхода:**

1. Реализованы минимум четыре специалиста: `XssSpecialist`, `SqliSpecialist`, `SstiSpecialist`, `IdorSpecialist`. (LFI, XXE, SSRF, CmdInj — желательно, но могут быть скелетами.)
2. Каждый специалист опирается на общие модули `reflection_analyzer` и `filter_inferrer`.
3. Для XSS работает `BrowserVerifier` на Playwright headless Chromium: payload выполняется в контексте страницы, возвращается evidence (alert / DOM mutation / console / screenshot-path).
4. Гибридная генерация payloads: детерминированные наборы в `penage/payloads/*.yaml` + LLM-мутация, условленная на выход фильтр-инференции.
5. Интеграционный тест: на локальном DVWA-подобном моке каждый специалист находит свою уязвимость и validation-слой подтверждает её end-to-end.
6. В summary по каждой находке есть `evidence`-блок с типом evidence и ссылкой на артефакт (html / screenshot / http trace).

### Задачи

**2.1 — Общие модули инференции.**  
Файлы: `penage/analysis/reflection.py`, `penage/analysis/filter_inference.py`, `penage/analysis/context.py`.

- `ReflectionAnalyzer` — параллельная инъекция canary-токенов, поиск в HTTP-ответах и в DOM, классификация: `reflected` / `stored` / `none`; контекст — `html_body`, `attribute_quoted`, `attribute_unquoted`, `js_string`, `js_code`, `url`.
- `FilterInferrer` — сужающие пробы: какие теги, события, спец-символы, кодировки режутся. Возвращает `FilterModel`.

**2.2 — `BrowserVerifier`.**  
Файлы: `penage/verify/browser.py`, `penage/verify/__init__.py`.  
Playwright sync API, headless Chromium. Вход: URL + дополнительные HTTP-параметры / body / cookies. Наблюдение: `dialog` events, `console` events, `page.evaluate(...)` для DOM-проверок, скриншот при успехе. Результат — структура `BrowserEvidence(kind, details, artefact_path)`. Playwright добавить в `pyproject.toml` как опциональную dep-группу `browser`; без неё `BrowserVerifier` падает понятной ошибкой при инициализации.

**2.3 — Payload-наборы.**  
Файлы: `penage/payloads/xss.yaml`, `sqli.yaml`, `ssti.yaml`, `idor.yaml`.  
Структура записи:

```yaml
- id: xss-attr-break-1
  context: attribute_quoted
  payload: '" onfocus=alert(1) autofocus x="'
  notes: breaks out of double-quoted attribute
```

Наборы — небольшие (20–40 на класс), качественные, с пометками о контексте. Остальное делает LLM-мутация.

**2.4 — Специалисты.**  
Файлы: `penage/specialists/xss.py`, `sqli.py`, `ssti.py`, `idor.py`.  
Структура каждого — пять фаз AWE:

```
Phase 1: parallel canary injection
Phase 2: context analysis      (ReflectionAnalyzer)
Phase 3: filter inference       (FilterInferrer)
Phase 4: payload mutation       (deterministic + LLM-conditioned)
Phase 5: verification           (BrowserVerifier для XSS;
                                 timing/error-based для SQLi;
                                 engine-probes для SSTI;
                                 differential auth requests для IDOR)
```

Каждая фаза — отдельный метод, с отдельной точкой для trace-события. `PayloadHistory` используется для дедупа.

**2.5 — Дополнительные специалисты.**  
Файлы: `lfi.py`, `xxe.py`, `ssrf.py`, `cmdinj.py`.  
Минимум для этого этапа — скелеты + базовые probes. Полировка возможна позже отдельной итерацией.

**2.6 — Интеграционный тест.**  
Файлы: `tests/integration/test_dvwa_like_mock.py`, `tests/fixtures/dvwa_like/`.  
Поднять httpx-WSGI-мок с поведением DVWA low-level: reflected xss, error-based sqli, simple ssti, горизонтальный idor. Прогнать каждого специалиста, проверить evidence.

### Замечания по дизайну

- XSS без браузерной верификации не считается solved. Это ключевое отличие от baseline LLM-агентов и ядро защиты от ложных срабатываний (AWE §IV.B, §IV.C).
- LLM-мутация получает на вход не «придумай payload», а структурированный контекст: текущий контекст инъекции + модель фильтра + список уже неудачных payload’ов. Это снижает галлюцинации (CAI §6, «Reducing Ambiguity»).
- Для SQLi blind использовать `pg_sleep` / `SLEEP` / `WAITFOR` + статистическая проверка (минимум 3 пробы с контролем), не единичное измерение.
- Browser-verification работает против `--base-url`; для безопасности не переиспользовать основной session-jar без явного передачи.

---

## Этап 3 — Multi-agent MAPTA-style

**Статус:** ⬜  
**Цель:** разделить текущего моноагента на три роли с изолированными LLM-контекстами.  
**Условия входа:** этап 2 закрыт (иначе Validation-агенту нечего валидировать).  

**Условия выхода:**

1. В коде есть три отдельные роли: `CoordinatorAgent`, `SandboxAgent`, `ValidationAgent`. Каждая — с собственным system prompt и собственным срезом `UsageTracker`.
2. Sandbox-агенты (от 1 до N) делят один Docker-контейнер, но имеют изолированные LLM-контексты.
3. Validation-агент — обязательный gate. Находка попадает в summary только после его `pass`.
4. Summary раскладывает cost/tokens/latency по ролям.
5. Режим `safe-http` продолжает работать как single-agent (Coordinator-only, без Sandbox) — backward compat.
6. Интеграционный тест демонстрирует разделение ролей и вызов Validation.

### Задачи

**3.1 — Абстракция агента.**  
Файлы: `penage/core/agent.py`.  
Базовый класс `Agent` с полями: `role`, `system_prompt`, `llm_client`, `tool_set`, `context_window`, `usage_tracker`. Метод `step(observation) -> action`.

**3.2 — Три роли.**  
Файлы: `penage/agents/coordinator.py`, `sandbox_agent.py`, `validation_agent.py`; промты — в `penage/prompts/coordinator.txt` и т.д.  
Coordinator видит высокоуровневую картину и выбирает специалиста/макрос. Sandbox выполняет узкую подзадачу. Validation получает candidate PoC и возвращает pass/fail с evidence.

**3.3 — Координация.**  
Файлы: `penage/core/orchestrator.py` (переработка).  
Текущий Orchestrator превращается в «шину»: принимает от Coordinator решения «делегировать специалиста X / выполнить tool Y / передать PoC Validation». Пул Sandbox-агентов — ленивый, создаётся при первой делегации.

**3.4 — Параллельность Sandbox.**  
Файлы: `penage/core/sandbox_pool.py`.  
`ThreadPoolExecutor` с ограничением по числу одновременных sandbox-агентов (default 2). Docker-контейнер один; блокировки — только по непараллелящимся ресурсам (например, порт).

**3.5 — Validation gate.**  
Файлы: `penage/validation/gate.py`.  
Любой candidate finding проходит через `ValidationGate.validate(finding) -> ValidationResult`. Gate вызывает ValidationAgent; тот, в свою очередь, может дёрнуть `BrowserVerifier` или запустить PoC-скрипт в sandbox. В `summary.findings` — только те, что прошли gate.

**3.6 — Backward compat.**  
`safe-http` эпизод остаётся одноагентным: Coordinator напрямую вызывает HTTP-tools, без Sandbox-агентов. Validation в `safe-http` редуцирован до HTTP-валидации (без запуска exploit-скриптов).

### Замечания по дизайну

- Изоляция LLM-контекста — именно то, о чём пишет MAPTA §2.1 («isolated LLM context»). Не переиспользовать общий чат-history между ролями.
- Prompt для Validation-агента должен явно запрещать ему искать новые уязвимости — только подтверждать/опровергать переданную кандидатную. Это защита от «hallucinated findings».
- Thread-safety `UsageTracker` — обязательна на этом этапе (на этапе 1 это было nice-to-have).

---

## Этап 4 — Реальный G-CTR

**Статус:** ⬜  
**Цель:** построить закрытый цикл attack graph → Nash equilibrium → digest → system prompt Coordinator’а.  
**Условия входа:** этап 3 закрыт.  

**Условия выхода:**

1. Модуль `penage/graph/` строит attack graph из JSONL-трассы.
2. LLM-экстрактор графа срабатывает каждые `N` взаимодействий (default `N=5`), производит валидный DAG (NetworkX).
3. Реализован CTR-солвер: минимакс, Poisson `λ_a=2` / `λ_d=1`, возвращает defender mix, attacker paths, equilibrium probability.
4. Digest-генератор в двух режимах: `algorithmic` (шаблон на порогах `p>0.9` / `p<0.95`) и `llm` (350-словный структурированный промт, `temperature=0.3`, fallback → `algorithmic` при ошибке).
5. Digest инжектится в system prompt Coordinator’а каждые `N` шагов.
6. A/B эксперимент: 20+ эпизодов на локальном моке, четыре конфигурации (`digest off` / `algorithmic` / `llm` × два сценария). В summary — сравнение success rate и variance.
7. `gctr_lite` переименован в `heuristic_ranking`, либо удалён, либо поглощён новым модулем.

### Задачи

**4.1 — Attack graph.**  
Файлы: `penage/graph/model.py`, `penage/graph/builder.py`, `penage/graph/sanitize.py`.  
`Node(id, name, info, vulnerability: bool, message_id)`, `Edge(source, target, score)`.  
Sanitize: удалить циклы через `networkx.all_simple_paths`, обрезать non-vulnerable leaves, добавить artificial `leaf_X` с probability 1.0 к каждому vulnerable, слить стартовые точки в `node_1`, убрать входящие рёбра в `node_1`.

**4.2 — LLM-экстрактор.**  
Файлы: `penage/graph/llm_extractor.py`, `penage/prompts/graph_extraction.txt`.  
Промт — в духе CAI Appendix B. Вход — последние `N` трассовых событий. Выход — JSON с `nodes` / `edges`, парсинг через pydantic с валидацией схемы. Кап на размер графа: piecewise-linear scaling по числу сообщений (CAI §3.1.4), clamp `[4, 25]`.

**4.3 — CTR-солвер.**  
Файлы: `penage/graph/ctr_solver.py`.  
Зависимости: `networkx`, `scipy`. Poisson-вероятности по формуле (9) из CAI. Минимакс через LP: переменные — `σ_d(c)` для `c ∈ AS1`; ограничение — вероятность перехвата `≥ v` для каждого пути; цель — `maximize v`. Возвращает `CTRResult(defender_mix, attacker_paths, game_value)`.

**4.4 — Effort scoring.**  
Файлы: `penage/graph/effort.py`.  
Формулы `ϕ_msg`, `ϕ_tok`, `ϕ_cost` из CAI §3.1.3. Веса в конфиге: `(w_msg, w_tok, w_cost)`. Для локальных моделей (Ollama) по умолчанию `w_cost = 0`, веса пересчитываются до симплекса.

**4.5 — Digest-генератор.**  
Файлы: `penage/graph/digest.py`, `penage/prompts/digest.txt`.  
Методы: `generate_algorithmic(ctr_result, graph) -> str` и `generate_llm(ctr_result, graph, llm_client) -> str`. LLM-вариант: `temperature=0.3`; при исключении → algorithmic fallback. Выход — markdown-блок с секциями Attack Paths / Bottlenecks (`p<0.95`) / Critical Nodes / High-Risk Transitions (`p>0.9`) / Tactical Guidance.

**4.6 — Инъекция в system prompt.**  
Файлы: `penage/agents/coordinator.py`, `penage/core/orchestrator.py`.  
Каждые `N` шагов: пересобрать attack graph из трассы → solve → digest → заменить «G-CTR»-секцию в system prompt Coordinator’а. Старый digest вытесняется полностью (не накапливаем).

**4.7 — A/B инфраструктура.**  
Файлы: `penage/experiments/ab.py`, `tests/integration/test_digest_ab.py`.  
Хелпер гоняет тот же сценарий в K конфигурациях и выдаёт таблицу success rate / avg tools / variance. Для воспроизводимости — фиксированные seeds для LLM-temperature и для моков.

**4.8 — Уборка.**  
Файлы: `penage/policy/gctr_lite.py` → `penage/policy/heuristic_ranking.py` (либо содержимое мержится в новый G-CTR — решать по ходу).

### Замечания по дизайну

- LP может быть вырожденным (один путь, нет развилок); обработать отдельно — возвращать `defender_mix=[]`, `game_value=0`.
- Графы, построенные LLM, часто содержат дубли узлов. Добавить дедуп по семантическому имени (лёгкая нормализация: lowercase, strip punctuation) перед CTR-решением.
- Не инжектить digest, пока в графе меньше трёх уязвимых путей — это шум.
- Инъекция digest — в system prompt, не в user. CAI эмпирически показывает, что user-prompt и assistant-prompt дают худшие результаты (CAI §3.2, footnote 2).

---

## Этап 5 — Бенчмарки и отчётные цифры

**Статус:** ⬜  
**Цель:** подтвердить интеграцию измеримыми цифрами на тех же тестовых полигонах, что используют оригинальные статьи.  
**Условия входа:** этапы 1–4 закрыты.  

**Условия выхода:**

1. Работающий раннер XBOW: поднимает контейнер из `validation-benchmarks`, запускает эпизод, извлекает флаг, собирает метрики.
2. Работающий раннер DVWA: low / medium / high × 5 классов уязвимостей.
3. Отчётный формат в JSON + markdown: per-category solve rate, time-to-solve, tokens/solve, cost/solve, variance.
4. Ablation study: три независимых ablation’а (без G-CTR digest, без browser verification, без persistent memory) с минимум 15 прогонов на конфигурацию.
5. Опубликованные цифры в `docs/evaluation.md`.

### Задачи

**5.1 — XBOW-раннер.**  
Файлы: `penage/benchmarks/xbow.py`, `penage/benchmarks/common.py`.  
Форк-совместимые правки для устаревших XBOW-образов (при необходимости — в `docker/xbow-patches/`). Параллельный запуск ограничен (начать с 1). Таймаут 10 минут на челлендж.

**5.2 — DVWA-раннер.**  
Файлы: `penage/benchmarks/dvwa.py`.  
Поднимает DVWA, выставляет security level, прогоняет связку specialist → validation на каждом vector, собирает метрики.

**5.3 — A&D-раннер (только если активирован этап 6).**  
Файлы: `penage/benchmarks/ad_ctf.py`.

**5.4 — Отчёты.**  
Файлы: `penage/benchmarks/report.py`, `docs/evaluation.md`.  
Функции `render_markdown(results) -> str` и `render_json(results) -> dict`. Markdown — в стиле Table III AWE / Table 2 MAPTA.

**5.5 — Ablation harness.**  
Файлы: `penage/experiments/ablation.py`.  
Три конфигурации: `baseline` vs `without-X`. Одинаковые seeds. Хелпер для статистической значимости (минимум t-test через `scipy.stats`).

### Замечания по дизайну

- Репортинг должен быть детерминированным: одинаковые входы → одинаковый отчёт. Для LLM это означает `temperature=0` где возможно и фиксацию seed во всех моках.
- XBOW-образы частично устарели (MAPTA §3 починили 43 из 104). При столкновении — документировать patch в `docker/xbow-patches/`.

---

## Этап 6 — A&D и Purple G-CTR_merged (опционально)

**Статус:** ⬜  
**Цель:** реализовать attack-and-defense режим с общим графом для red/blue.  
**Условия входа:** этап 5 закрыт.  

**Условия выхода:**

1. Реализован `BlueAgent` — симметричная red’у роль; задача — блокировать атаки и поддерживать uptime.
2. Три конфигурации: `red_only`, `dual_independent`, `purple_merged` (shared context + shared graph).
3. Экспериментально показано: `purple_merged` бьёт `dual_independent` по соотношению побед.

### Задачи

**6.1 — BlueAgent.** Файлы: `penage/agents/blue.py`, `penage/prompts/blue.txt`.  
**6.2 — Shared graph mode.** Файлы: `penage/graph/shared.py` — атомарный общий attack-graph-объект, read/write из обеих ролей.  
**6.3 — A&D scenarios.** Файлы: `penage/scenarios/cowsay/`, `penage/scenarios/pingpong/` — docker-compose с уязвимыми сервисами, scoring-раннер.  
**6.4 — Эксперименты.** Файлы: `penage/experiments/purple.py`.  

### Замечания по дизайну

- `purple_merged` — ключевой breakthrough из CAI §4.4.2. Если время ограничено — этап можно отложить; основной claim работы он не ломает.

---

## Backlog (вне этапов)

Идеи, которые могут появиться позже; не включать в активные этапы без явного решения.

- **Адаптивная генерация графа:** не фиксированный `N=5`, а по энтропии изменений состояния.
- **Chrome Extension / MCP-интеграция:** когда browser verification нужна на реальных продуктивных сценариях.
- **Fine-tuned LLM на трассах penage:** когда накопится достаточно данных для supervised fine-tuning генерации payload’ов.
- **Coverage-guided exploration:** элементы grey-box тестирования через прокси-инструментацию.
- **CVE-ready vulnerability reporting:** автогенерация reports в стандартных форматах.
- **Мягкая интеграция с MITRE ATT&CK:** маркировка шагов атаки тактиками/техниками для отчётов.

---

## Как закрывать этап

1. Все задачи этапа выполнены.
2. `pytest -q` зелёный.
3. Добавлен/обновлён раздел в `docs/architecture.md`.
4. `CLAUDE.md` обновлён (секция «Статус этапов»).
5. В `docs/roadmap.md` статус этапа переведён в ✅.
6. Commit с сообщением `etap N: <краткое описание>`.
7. Новый этап открывается только после этого.
