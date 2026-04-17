# CLAUDE.md

Это справочный документ для Claude Code и для людей, работающих над `penage`.
Перед любой нетривиальной задачей прочитай этот файл и `docs/roadmap.md`.

## Что за проект

`penage` — агентский runtime для авторизованного веб-пентеста, синтезирующий идеи трёх исследований:

- **AWE** (Adaptive Web Exploitation) — специализированные агенты под конкретные классы уязвимостей, пятифазные пайплайны, браузерная верификация, персистентная память.
- **MAPTA** (Multi-Agent Penetration Testing AI) — разделение ролей Coordinator / Sandbox / Validation, per-job Docker, строгий resource accounting.
- **CAI / G-CTR** — автоматическое построение attack graph из трасс, вычисление Nash-равновесия, инъекция стратегического дайджеста в цикл планировщика.

Текущая реализация — это **скелет**, закрывающий только базовую оркестрацию и recon/auth часть. Полный план достройки — в `docs/roadmap.md`.

## Безопасность и этика

Runtime предназначен **только для авторизованных целей**: CTF, локальные лаборатории, внутренние training-окружения, явно санкционированный пентест.

Требования, которые должны выполняться кодом и никогда не ослабляться:

1. Guard-слой (`penage/core/guards.py`) фильтрует URL по allow-list хостов. Не добавлять обходов без явного обсуждения.
2. `safe-http` — режим по умолчанию. Тихо повышать уровень execution privilege запрещено.
3. Санбокс-режим с Docker использует изолированный per-job контейнер. Переиспользование контейнера между эпизодами — нарушение модели угроз MAPTA.
4. Любой специалист, потенциально выполняющий деструктивные операции (`DROP`, `DELETE`, `rm -rf` и т.п.), должен иметь явный опт-ин флаг и писать warning в трассу.
5. Никаких hard-coded API-ключей, cookies, токенов в коммитах. Все секреты — через env (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`).

## Архитектурные инварианты

Эти правила не должны нарушаться ни одним изменением без явного обсуждения:

1. **Разделение слоёв.** `app → core → {tools, specialists, policy, macros, validation, sandbox}`. Никаких обратных зависимостей: `tools` не знает про `specialists`, `specialists` не знают про `app`. LLM-клиенты импортируются только через `penage/llm/base.py::LLMClient`.

2. **Типизированное состояние.** Новый код пишет в типизированные поля `State` (dataclass'ы), а не в `State.facts`. `State.facts` оставлен для обратной совместимости и свободных notes; новые данные туда **не** добавляются. Если типа под твои данные нет — создаётся новый dataclass в `penage/core/state.py`.

3. **Specialist-паттерн AWE.** Новый специалист под класс уязвимостей реализует пять фаз: (1) canary / probe injection, (2) context analysis, (3) filter / defense detection, (4) payload mutation, (5) evidence-gated verification. Отклонения от пятифазного паттерна допускаются, но обосновываются в docstring класса.

4. **Validation gate.** Ни одна находка не попадает в summary как `solved` без прохождения валидации. Для XSS валидация = браузерное исполнение. Для SQLi = извлечение данных или детерминированный timing-сигнал. Для SSRF = подтверждённый исходящий запрос. Для IDOR = дифференциальный тест. Теоретические находки записываются как `candidate`, не `solved`.

5. **Трасса — единственный источник истины для эпизода.** Всё, что нужно для воспроизведения эпизода или построения attack graph, должно уйти в JSONL-трассу. Если данных нет в трассе — их нет.

6. **Ресурсный учёт — по ролям.** Когда появятся Coordinator / Sandbox / Validation агенты (Stage 3), токены, tool calls и время считаются отдельно по каждой роли. Это необходимо для корректного сопоставления с цифрами из MAPTA.

7. **Имена соответствуют содержанию.** Модуль, который называется `gctr_*`, либо реализует G-CTR (пусть в урезанной форме), либо переименовывается. Сейчас `policy/gctr_lite.py` — обычный эвристический ranker, это исправляется в Stage 4.

8. **Ablation-совместимость.** Каждая крупная фича добавляется с возможностью выключить через CLI-флаг (`--no-memory`, `--gctr-mode off`, `--no-browser-verify`). Нужно для корректных ablation studies в Stage 5.

9. **Per-role / per-specialist usage attribution.** Каждый LLM-вызов атрибутируется дважды: в `by_role[<role>]` (`"coordinator"`, `"sandbox"`, `"validation"`) и в `by_specialist[<name>]`, если вызов идёт через `RoleTaggedLLMClient` с выставленным `specialist_name`. `by_specialist` — **диагностическая** карта: она НЕ суммируется в totals (totals строится только из `by_role`), чтобы избежать двойного учёта. Proxy-клиенты создаются в `build_sandbox_agents(llm)`; в `SpecialistManager` каждый LLM-специалист получает СВОЙ proxy (не общий `llm`).

10. **Agents — proxies, не логика.** Agents-слой (`CoordinatorAgent`, `SandboxAgent`, `ValidationAgent`) — это тонкие обёртки вокруг `LLMClient` + system_prompt + role-tagging. Бизнес-логика пентест-пайплайна (планирование действий, выбор веток, генерация payload'ов) живёт: для coordinator — в `Planner`/`Planner`-like decomposition; для sandbox — в `Specialist`-реализациях (AWE 5-phase pipeline); для validation — в `EvidenceValidator` + `ValidationGate` (HTTP-cascade). SandboxAgent в Orchestrator хранится как словарь proxy-клиентов, но поведение действий специалиста всё ещё у Specialist.

11. **Episode = single Docker container lifetime.** В sandboxed-режиме daemon-контейнер создаётся **один раз** на эпизод и переиспользуется всеми sandbox-вызовами. Создание — ленивое (при первом exec); уничтожение — гарантированное через `try/finally` + `tools.aclose()` в `run_episode`. Безопасность контейнера закреплена в `DockerSandbox._base_docker_run_args` и включает: `--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--memory-swap = --memory`, `--ulimit fsize/nofile/nproc`, `--pids-limit`, `--log-driver none`, `--init`, non-root `--user`. Persistent=False-путь существует для ephemeral fallback (например, в тестах) и использует те же hardening-флаги.

## Известный технический долг

- `State.facts` несёт слишком много кросс-шаговой метаданных. План миграции — Stage 1.1.
- `policy/gctr_lite.py` — эвристика, а не G-CTR. Будет переписано/переименовано в Stage 4.
- Часть специалистов — заглушки. Видно по покрытию тестами и TODO-маркерам.
- LLM-бэкендов кроме Ollama нет. Все три исходные статьи показывают сильную зависимость результата от модели — для воспроизведения их цифр нужны Anthropic / OpenAI клиенты. План — Stage 1.2.

## Рабочий процесс

### Перед любым изменением

1. Прочитай `docs/roadmap.md`, определи, к какому этапу относится задача.
2. Прочитай релевантные существующие файлы — структура и соглашения в них важнее общих гайдов.
3. Если задача меняет инвариант из списка выше — остановись и эскалируй обсуждение, не обходи молча.

### Во время изменения

1. Типизируй всё: возвращаемые значения, параметры, поля. Python 3.10+, поэтому `list[str]`, `dict[str, int]`, `X | None` без `Optional`.
2. Новый функциональный модуль = новый unit-тест рядом. Интеграционный тест — если модуль меняет episode lifecycle.
3. Никаких новых полей в `State.facts`. Новые данные → новый dataclass → `state.py`.
4. LLM-вызовы идут через `LLMClient`. Прямые вызовы Ollama / Anthropic / OpenAI SDK в прикладном коде запрещены.
5. Любой побочный эффект (HTTP-запрос, запись файла, выполнение в санбоксе) порождает событие в трассе. Не «тихих» действий.

### После изменения

1. `pytest -q` — зелёный.
2. `python -m penage.app.run_one --help` работает.
3. Если менялся lifecycle или инвариант — обнови `docs/architecture.md`.
4. Если закрыт пункт roadmap — пометь его как done в `docs/roadmap.md`.

### Перед коммитом

1. Secrets не попадают в репо (проверь `.gitignore`, API-ключи, cookies).
2. `runs/`, `*.jsonl`, `*.summary.json` из локальных прогонов — не коммитятся.
3. Коммиты атомарны: один коммит = одна логическая единица изменений из roadmap.

## Code style

- Python 3.10+. Type hints везде.
- Dataclasses для состояния, не dicts.
- Один специалист — один файл в `penage/specialists/`.
- Тесты рядом с кодом, зеркальная структура в `tests/unit/` и `tests/integration/`.
- Публичные API классов и функций — с docstring'ом, включая контракт возвращаемого значения и побочные эффекты.
- Имена: `snake_case` для функций/модулей, `PascalCase` для классов, `UPPER_SNAKE` для констант.
- Импорты: stdlib → third-party → local, отсортированы внутри группы.
- Логирование через `logging`, не `print` (кроме CLI-entrypoints).

## Команды

```bash
# Установка для разработки
pip install -e .[dev]

# Все тесты
pytest -q

# Только unit
pytest tests/unit -q

# Только integration
pytest tests/integration -q

# Запуск одного эпизода на локальном таргете
python -m penage.app.run_one \
  --base-url http://localhost:8080 \
  --ollama-model llama3.1 \
  --max-steps 20 \
  --trace runs/trace.jsonl \
  --summary-json runs/summary.json

# Справка по CLI
python -m penage.app.run_one --help
```

После Stage 1.2 появится также:

```bash
# С Anthropic (актуальный model string сверяй на docs.claude.com)
python -m penage.app.run_one \
  --base-url http://localhost:8080 \
  --llm-backend anthropic \
  --anthropic-model <current-sonnet-model-id> \
  ...
```

## Карта репозитория

```
penage/
  app/          CLI, wiring, summary
  core/         state, planner, orchestrator, guards, tracer
  llm/          LLM clients (base, fake, ollama; anthropic/openai — Stage 1.2)
  macros/       multi-step procedures
  policy/       action arbitration (gctr_lite — переделывается в Stage 4)
  sandbox/      null / docker backends
  specialists/  candidate generators (recon/auth сейчас; vuln-агенты — Stage 2)
  tools/        http / curl / sandbox execution
  utils/
  validation/   evidence & validated-signal recording
  memory/       persistent memory — появляется в Stage 1.4
  gctr/         attack graph + Nash + digest — появляется в Stage 4
  agents/       Coordinator/Sandbox/Validation — появляется в Stage 3
  analyzers/    reflection/filter — появляются в Stage 2
  payloads/     hybrid payload system — появляется в Stage 2

docs/
  architecture.md     живой архитектурный обзор
  roadmap.md          детальный план достройки
  user-guide.md

tests/
  unit/
  integration/

benchmarks/              появляются в Stage 5
  xbow.py
  dvwa.py
  ad_ctf.py
  metrics.py
```

## Roadmap — краткий чеклист

| Stage | Цель | Статус |
|-------|------|--------|
| 1. Foundation | Типизированное состояние, LLM-бэкенды, accounting, память | ✅ |
| 2. AWE specialists | Vuln-специалисты + браузерная верификация + гибридные payload'ы | ✅ |
| 3. MAPTA multi-agent | Разделение ролей Coordinator/Sandbox/Validation | ✅ |
| 4. G-CTR closed loop | Attack graph + Nash + digest injection | 🔲 |
| 5. Benchmarks | XBOW / DVWA / A&D + ablations | 🔲 |
| 6. Purple A&D | Red+Blue с общим attack graph (опционально) | 🔲 |

Детали, условия входа/выхода и список файлов по каждому этапу — в `docs/roadmap.md`.

## Связь с исследовательской базой

Когда сомневаешься в том, как делать конкретный компонент — сверяйся с соответствующей статьёй:

- Пятифазный пайплайн, filter inference, hybrid payloads, browser verification → **AWE**.
- Разделение ролей агентов, per-job Docker, cost/correlation-анализ, validation gate → **MAPTA**.
- Attack graph extraction, Nash equilibrium, effort-scoring, digest generator, closed-loop injection → **CAI / G-CTR**.

Безопасные отклонения от статей допустимы, но документируются в `docs/roadmap.md` в разделе «Открытые вопросы» с аргументацией.
