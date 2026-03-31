# Архитектура

## Обзор

`penage` — это агентный runtime для авторизованных веб-лабораторных целей.
Архитектура проекта разделена на слои так, чтобы планирование, исполнение, валидация и сборка runtime были отделимы друг от друга.

На высоком уровне один episode выглядит так:

```text
CLI / run_one
  -> runtime factory / bootstrap
  -> Orchestrator
     -> specialists предлагают кандидатов
     -> planner запрашивает у LLM план действий
     -> policy ранжирует и выбирает действия
     -> tools/macros исполняют действия
     -> state updater проецирует observations в state
     -> validator фиксирует evidence
     -> tracer пишет события в trace
     -> summary builder формирует итоговый summary JSON
```

## Карта слоёв

### `penage.app`

Отвечает за запуск и композицию runtime:

- разбор CLI-аргументов
- построение `RuntimeConfig`
- wiring sandbox, tools, LLM, specialists, macros, policy и orchestrator
- построение итогового summary JSON

Ключевые модули:

- `config.py`
- `runtime_factory.py`
- `bootstrap.py`
- `run_one.py`
- `summary.py`

### `penage.core`

Содержит основной runtime-домен:

- типы действий и наблюдений
- planner
- orchestrator
- state и pipeline его обновления
- guard и фильтрацию URL
- генерацию planner context
- tracing

Ключевые модули:

- `actions.py`
- `observations.py`
- `state.py`
- `planner.py`
- `orchestrator.py`
- `state_updates.py`
- `tracer.py`

### `penage.tools`

Исполняет низкоуровневые действия.

Зоны ответственности:

- HTTP через `httpx`
- HTTP через curl внутри sandbox
- shell/python execution через sandbox
- маршрутизация действий в нужный backend

Ключевые модули:

- `http_tool.py`
- `curl_http_tool.py`
- `sandbox_tool.py`
- `runner.py`

### `penage.sandbox`

Реализации sandbox:

- `NullSandbox` — отключённый backend sandbox
- `DockerSandbox` — изолированный backend исполнения в Docker
- `SandboxExecutor` — детерминированная обёртка/валидатор над вызовами sandbox

### `penage.llm`

Слой абстракции LLM:

- `base.py` — protocol и типы сообщений/ответов
- `fake.py` — детерминированный клиент для тестов
- `ollama.py` — локальный клиент Ollama с улучшениями под JSON-ориентированные сценарии

### `penage.specialists`

Детерминированные и асинхронные генераторы candidate actions.
Они предлагают кандидатов на основе текущего `State`.

Примеры:

- `LoginWorkflowSpecialist`
- `NavigatorSpecialist`
- `ResearchSpecialist`
- `ResearchLLMSpecialist`
- `AuthSessionConfusionSpecialist`
- `CurlReconSpecialist`
- `SandboxSmokeSpecialist`

Менеджер и pipeline:

- `manager.py`
- `proposal_runner.py`
- `pipeline.py`

### `penage.policy`

Арбитраж между действиями planner и кандидатами от specialists.

Зоны ответственности:

- ранжирование candidate actions
- штрафы за повторные/негативные/рискованные действия
- предпочтение follow-up действий, согласованных с pivot или macro-контекстом
- выбор разнообразного батча действий

Ключевые модули:

- `gctr_lite.py`
- `ranking.py`
- `selection.py`
- `scoring.py`
- `helpers.py`

### `penage.macros`

Переиспользуемые многошаговые процедуры.
Macros — это более высокоуровневые примитивы исполнения, скрывающие повторяющуюся HTTP probing-логику.

Текущее семейство macros:

- `replay_auth_session`
- `follow_authenticated_branch`
- `probe_resource_family`

Общие helper-функции:

- `probe_support.py`

### `penage.validation`

Логика валидации и evidence.

Зоны ответственности:

- выявление сильных сигналов, например flag-like output
- подавление ложных срабатываний, например статических ассетов или login-gate страниц
- запись evidence/validated signals в state и trace

## Жизненный цикл episode подробнее

### 1. Startup

`penage.app.run_one`:

- разбирает CLI-аргументы
- строит `RuntimeConfig`
- создаёт `JsonlTracer`
- вызывает `build_runtime(...)`
- запускает один episode с user prompt, построенным из target base URL

### 2. Фаза предложений specialists

Если specialists включены, `SpecialistManager` собирает candidate actions.
Затем эти кандидаты дедуплицируются, ограничиваются по источникам и сохраняются как preview в `state.facts`.

### 3. Фаза planner

`Planner` строит planner context из текущего `State`, отправляет сообщения в LLM, парсит JSON и применяет фильтрацию через guard / URL guard / negative-memory.

### 4. Фаза policy

Если policy включена, `GctrLitePolicy` ранжирует и planner actions, и specialist candidates, после чего выбирает финальный батч действий.

### 5. Фаза исполнения

Действия исполняются через:

- `ToolRunner` для HTTP / shell / python / note
- `MacroExecutor` для macro actions

### 6. Фаза проекции и валидации

Observations проецируются обратно в state через pipeline обновления state.
Это обновляет, например:

- известные пути
- формы
- недавние неудачи
- лучшую HTTP-страницу
- promoted pivots
- recent HTTP memory
- счётчики валидации

### 7. Tracing и summary

События trace записываются в формате JSONL.
В конце episode формируется структурированный summary JSON.

## Режимы исполнения

## `safe-http`

Guard разрешает:

- `http`
- `note`

Используй этот режим, когда нужно более безопасное и узкое поведение исполнения.

## `sandboxed`

Guard разрешает:

- `http`
- `note`
- `shell`
- `python`
- `macro`

При использовании вместе с Docker sandbox localhost-подобные base URL переписываются для доступа из контейнера, а в качестве HTTP backend используется curl-вариант.

## Trace model

Tracer пишет JSONL-записи для:

- action
- observation
- note
- validation
- summary
- macro_start
- macro_substep
- macro_result

Это позволяет восстанавливать поведение episode постфактум и использовать trace как основной артефакт отладки.
