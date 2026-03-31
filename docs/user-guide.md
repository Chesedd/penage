# User Guide

## What this tool is for

`penage` runs an agent-style episode against an authorized web target.
It uses a planner, deterministic specialists, policy selection, and optional sandbox execution to explore the target and collect evidence.

Use it only for:

- CTF challenges
- internal labs
- training environments
- explicitly authorized security testing

## Before you start

You need:

- Python 3.10+
- Ollama running locally or reachable over HTTP
- a target base URL you are allowed to test
- Docker only if you want sandboxed Docker execution

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

For development and tests:

```bash
pip install -e .[dev]
```

## Basic run

```bash
python -m penage.app.run_one \
  --base-url http://localhost:8080 \
  --ollama-model llama3.1
```

This will:

- start one episode
- write a trace JSONL file
- write a summary JSON file
- print final notes, facts, trace path, and summary path

## Recommended first run

Start simple:

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

This keeps execution narrow while you verify the target and output format.

## Modes

### Safe HTTP mode

```bash
--mode safe-http
```

Use this when you want:

- only HTTP/note actions
- easier debugging
- lower execution risk

### Sandboxed mode

```bash
--mode sandboxed --sandbox-backend docker
```

Use this when you need:

- shell/python execution
- macro execution
- Docker-isolated sandbox steps

Example:

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

## Useful flags

### Output files

- `--trace runs/trace.jsonl`
- `--summary-json runs/summary.json`

### Budgets

- `--max-steps 30`
- `--max-http-requests 30`
- `--max-total-text-len 200000`
- `--actions-per-step 1`

### Execution behavior

- `--enable-specialists`
- `--policy on`
- `--allow-static`

### Networking

- `--allowed-host internal.example`
- `--sandbox-backend docker`
- `--docker-network bridge`

## How to read the trace

The trace is JSONL.
Each line is an event.
Typical events include:

- action
- observation
- note
- validation
- summary

Use it when you want to understand:

- what the planner proposed
- what policy selected
- what the tools executed
- which observations changed state
- where evidence came from

## How to read the summary

The summary JSON is the easiest high-level report.
It includes:

- experiment config
- final counters
- best HTTP page and IDs
- policy source counts
- validation totals
- usage metrics
- previews of research, recent failures, auth confusion, and macro results

## Troubleshooting

### Ollama is not reachable

Symptoms:

- startup works but LLM calls fail
- request/connection errors from the Ollama client

Check:

- Ollama is running
- `--ollama-url` is correct
- the model in `--ollama-model` exists locally

### No summary file appears

Check:

- the trace path directory is writable
- the process reached the normal episode end path
- you did not interrupt the process before summary writing

### Docker sandbox does not reach localhost target

When sandboxed Docker mode is used, localhost-style base URLs are rewritten for container access.
Still verify:

- Docker is installed and running
- the target is reachable from the Docker network mode you selected
- `--docker-network bridge` or `host` fits your local environment

### The run stops too early

Try increasing:

- `--max-steps`
- `--max-http-requests`
- `--max-total-text-len`

and enable:

- `--enable-specialists`
- `--policy on`

## Recommended operator workflow

1. Run in `safe-http` first.
2. Confirm trace and summary are generated.
3. Enable specialists.
4. Enable policy.
5. Switch to sandboxed Docker mode only when sandbox-capable actions are needed.
6. Keep traces and summaries for later analysis.
