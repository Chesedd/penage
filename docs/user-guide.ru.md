# Руководство пользователя

## Для чего нужен этот инструмент

`penage` запускает agent-style episode против авторизованной веб-цели.
Он использует planner, детерминированных specialists, policy selection и опциональное sandbox execution для исследования цели и сбора evidence.

Использование разрешается лишь для:

- CTF-задач
- внутренних лабораторий
- учебных сред
- явно разрешённого security-тестирования

## Перед началом

Требуется:

- Python 3.10+
- запущенный локально Ollama или Ollama, доступный по HTTP
- target base URL, который тебе разрешено тестировать
- Docker, только если нужен sandboxed Docker execution

## Установка

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

Для разработки и тестов:

```bash
pip install -e .[dev]
```

## Базовый запуск

```bash
python -m penage.app.run_one \
  --base-url http://localhost:8080 \ (подставить свою ссылку на задачу)
  --ollama-model llama3.1            (подставить свою модель)
```

Это:

- запустит один episode
- создаст trace JSONL-файл
- создаст summary JSON-файл
- выведет финальные notes, facts, trace path и summary path

## Рекомендуемый первый запуск

```bash
python -m penage.app.run_one \
  --base-url http://localhost:8080 \
  --ollama-model llama3.1 \
  --mode safe-http \
  --max-steps 10 \
  --max-http-requests 10 \
  --trace runs/trace.jsonl \
  --summary-json runs/summary.json
```

Такой запуск сужает поведение исполнения, пока ты проверяешь цель и формат выходных данных.

## Режимы

### Режим Safe HTTP

```bash
--mode safe-http
```

Использовать, когда тебе нужно:

- только `http`/`note` действия
- более простая отладка
- более низкий риск исполнения

### Режим Sandboxed

```bash
--mode sandboxed --sandbox-backend docker
```

Использовать, когда нужны:

- shell/python execution
- macro execution
- изолированные шаги в Docker sandbox

Пример:

```bash
python -m penage.app.run_one \
  --base-url http://localhost:8080 \
  --ollama-model llama3.1 \
  --mode sandboxed \
  --sandbox-backend docker \
  --docker-network bridge \
  --enable-specialists \
  --policy on
```

## Полезные флаги

### Выходные файлы

- `--trace runs/trace.jsonl`
- `--summary-json runs/summary.json`

### Бюджеты

- `--max-steps 30`
- `--max-http-requests 30`
- `--max-total-text-len 200000`
- `--actions-per-step 1`

### Поведение исполнения

- `--enable-specialists`
- `--policy on`
- `--allow-static`

### Сеть

- `--allowed-host internal.example`
- `--sandbox-backend docker`
- `--docker-network bridge`

## Как читать trace

Trace хранится в JSONL.
Каждая строка — это одно событие.
Типичные события:

- action
- observation
- note
- validation
- summary

Использовать trace, когда нужно понять:

- что предложил planner
- что выбрала policy
- что реально исполнили tools
- какие observations изменили state
- откуда появилось evidence

## Как читать summary

Summary JSON — самый удобный высокоуровневый отчёт.
В нём есть:

- конфигурация эксперимента
- финальные счётчики
- лучшая HTTP-страница и IDs
- policy source counts
- total по validation
- usage metrics
- preview research, recent failures, auth confusion и macro results

## Диагностика проблем

### Ollama недоступен

Признаки:

- startup проходит, но LLM-вызовы падают
- request/connection errors из Ollama client

Проверить:

- Ollama действительно запущен
- `--ollama-url` задан правильно
- модель из `--ollama-model` существует локально

### Не появляется summary-файл

Проверить:

- директория для trace path доступна на запись
- процесс дошёл до нормального завершения episode
- ты не прервал процесс до записи summary

### Docker sandbox не видит localhost-цель

Если используется sandboxed Docker mode, localhost-подобные base URL переписываются для доступа из контейнера.
Но всё равно проверить:

- Docker установлен и запущен
- цель достижима из выбранного Docker network mode
- `--docker-network bridge` или `host` подходит для твоей локальной среды

### Запуск останавливается слишком рано

Попробуй увеличить:

- `--max-steps`
- `--max-http-requests`
- `--max-total-text-len`

и включить:

- `--enable-specialists`
- `--policy on`

## Рекомендуемый рабочий сценарий оператора

1. Сначала запуск в `safe-http`.
2. Убедиться, что trace и summary действительно создаются.
3. Включить specialists.
4. Включить policy.
5. Переход в sandboxed Docker mode только когда нужны sandbox-capable actions.
6. Сохранение traces и summaries для последующего анализа.
