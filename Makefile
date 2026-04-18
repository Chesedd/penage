PYTHON ?= python

.PHONY: install install-dev test unit integration e2e slow run-help help

help:  ## Show available targets
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install:  ## Install runtime package
	$(PYTHON) -m pip install -U pip
	$(PYTHON) -m pip install -e .

install-dev:  ## Install package with dev extras
	$(PYTHON) -m pip install -U pip
	$(PYTHON) -m pip install -e .[dev]

test:  ## Default test suite (unit + integration; deselects e2e_dvwa + integration_slow)
	$(PYTHON) -m pytest -q

unit:  ## Unit tests only
	$(PYTHON) -m pytest -q tests/unit/

integration:  ## Integration tests, excluding e2e/
	$(PYTHON) -m pytest -q tests/integration/ --ignore=tests/integration/e2e

e2e:  ## E2E suite against a running DVWA (requires docker + python:3.12 image)
	$(PYTHON) -m pytest -m e2e_dvwa tests/integration/e2e/ -o addopts= -v

slow:  ## Slow / chromium-launching integration checks (marker: integration_slow)
	$(PYTHON) -m pytest -m integration_slow -o addopts= -v

run-help:  ## Show CLI help for run_one
	$(PYTHON) -m penage.app.run_one --help
