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

## Multi-agent архитектура (Stage 3)

Начиная со Stage 3 runtime организован как MAPTA-style трёхролевая
агентская система. `Orchestrator` выступает как шина: связывает роли,
хранит per-episode state и опосредует каждое действие + observation.
Каждая роль работает с изолированным LLM-контекстом и собственным
срезом usage-аккаунтинга.

### Диаграмма ролей

```text
┌─────────────────────────────────────────────────────────────┐
│                      Orchestrator (bus)                     │
│  ┌─────────────────┐  ┌───────────────┐  ┌──────────────┐   │
│  │ CoordinatorAgent│  │ SandboxAgents │  │ValidationGate│   │
│  │   (planning)    │  │ (proxy × 7)   │  │              │   │
│  └────────┬────────┘  └───────┬───────┘  └──────┬───────┘   │
│           │                   │                 │           │
│           ▼                   ▼                 ▼           │
│    plan actions        propose via        validate obs      │
│       (role=coordinator)   Specialist     http → agent*     │
│                       (role=sandbox,                        │
│                       specialist=<name>)  *if mode=agent    │
└─────────────────────────────────────────────────────────────┘
                      │ run_episode (tracker bound via ContextVar)
                      ▼
              DockerSandbox (per-episode persistent)
              + HttpTool + MemoryStore + JsonlTracer
```

- **CoordinatorAgent** — высокоуровневый планировщик. Принимает
  observation + planner context, выдаёт следующий план действий.
  Только роль coordinator вызывает planner-LLM. Role tag: `coordinator`.
- **SandboxAgent** — per-specialist LLM-proxy. `build_sandbox_agents(llm)`
  создаёт по одному `RoleTaggedLLMClient` на специалиста.
  `SpecialistManager` выдаёт каждому LLM-специалисту СВОЙ proxy
  (не общий клиент), чтобы токены атрибутировались per-specialist.
  Role tag: `sandbox`, `specialist=<name>` в per-specialist usage map.
- **ValidationAgent** — опциональный LLM-эскалатор, который
  `ValidationGate` поднимает, если HTTP-каскад оказался
  неконклюзивным. По контракту агент может только подтвердить или
  опровергнуть candidate finding — не предлагать новые. Role tag:
  `validation`.

### Поток одного шага

`run_episode → _run_step → _run_action`:

1. В начале шага — проверки budget, stop-condition и (опционально)
   correlation early-stop.
2. Specialists генерируют кандидатов параллельно через
   `SpecialistProposalRunner` (`asyncio.gather`); ablation — через
   `parallel_specialists=False`.
3. `CoordinatorAgent` выбирает действия (LLM-вызов под
   `role=coordinator`).
4. Policy-слой арбитрирует planner actions vs specialist candidates и
   формирует итоговый батч.
5. `_run_action` исполняет каждое действие из батча:
   - `tools.run(...)` либо `macros.run(...)`; fingerprint действия
     пишется в `UsageTracker`.
   - Observation проходит через `ValidationGate`: сначала HTTP-cascade,
     затем опциональная LLM-эскалация, если `validation_mode=agent`.
   - Делается memory attempt — outcome сохраняется для межэпизодного
     переиспользования.

### Per-episode Docker hardening

В sandboxed-режиме daemon-контейнер создаётся лениво при первом exec
и гарантированно уничтожается в `try/finally` через `tools.aclose()`
внутри `run_episode`. Все sandbox-вызовы внутри эпизода работают с
одним контейнером. Hardening — в
`DockerSandbox._base_docker_run_args`:

| Flag                    | Value                 | Purpose                          |
|-------------------------|-----------------------|----------------------------------|
| `--network none`        | (default)             | Network isolation                |
| `--read-only`           | rootfs read-only      | Tamper-resistant fs              |
| `--cap-drop ALL`        | —                     | Remove all Linux capabilities    |
| `--security-opt`        | no-new-privileges     | No suid escalation               |
| `--memory`              | `512m`                | RAM cap                          |
| `--memory-swap`         | = memory              | Disable swap bypass              |
| `--cpus`                | `1`                   | CPU share                        |
| `--pids-limit`          | `256`                 | Process cap (belt)               |
| `--ulimit nproc`        | `256:256`             | Process cap (suspenders)         |
| `--ulimit fsize`        | `64M:64M`             | Max file size (disk bomb guard)  |
| `--ulimit nofile`       | `256:256`             | Max open files                   |
| `--init`                | —                     | Zombie reaper                    |
| `--log-driver none`     | —                     | No log flooding                  |
| `--hostname`            | `penage-sandbox`      | No host leak                     |
| `--user`                | `1000:1000`           | Non-root                         |
| `--tmpfs /tmp`          | 64M, noexec, nosuid   | Ephemeral scratch                |
| `--tmpfs /workspace`    | 128M, nosuid          | Ephemeral workspace              |
| `-e HOME=/workspace`    | —                     | Writable HOME for non-root       |

`persistent=False` остаётся как ephemeral fallback (используется в
тестах) и применяет те же hardening-флаги.

### Correlation-based early stopping

Поверх raw cap-порогов есть три correlation-сигнала. Каждый
ablation-ready через `None`-дефолт.

- `max_no_evidence_steps` — стоп после N подряд идущих шагов без
  прироста `validation_evidence_count`.
- `max_policy_source_streak` — cap на `state.same_policy_source_streak`
  (как долго один источник policy доминирует в выборе действий).
- `max_action_repeat_ratio` — доля повторов в последних
  `action_repeat_window` действиях.

Snapshots снимаются в `UsageTracker.observe_step(state, step)` и
`UsageTracker.record_action_fingerprint(fp)`, проверяются через
`check_early_stop(thresholds)` перед каждым шагом.

### Ablation matrix

Каждый крупный рычаг multi-agent рантайма — ablation-ready. Каждый из
этих флагов проверяется в `tests/integration/test_e2e_ablation.py`.

| CLI flag                           | Default    | Effect when disabled/altered           |
|------------------------------------|------------|----------------------------------------|
| `--validation-mode {http,agent}`   | `http`     | `agent` turns on LLM escalation in gate|
| `--no-parallel-specialists`        | off        | Specialists executed sequentially      |
| `--max-no-evidence-steps INT`      | `None`     | Correlation stop off when None         |
| `--max-policy-source-streak INT`   | `None`     | Correlation stop off when None         |
| `--max-action-repeat-ratio FLOAT`  | `None`     | Correlation stop off when None         |
| `--action-repeat-window INT`       | `10`       | Window for repeat-ratio                |
| `--mode {sandboxed, safe-http}`    | CLI-driven | sandboxed → DockerSandbox persistent;  |
|                                    |            | safe-http → NullSandbox / ephemeral    |

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
