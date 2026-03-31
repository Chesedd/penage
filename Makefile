PYTHON ?= python

.PHONY: install install-dev test run-help

install:
	$(PYTHON) -m pip install -U pip
	$(PYTHON) -m pip install -e .

install-dev:
	$(PYTHON) -m pip install -U pip
	$(PYTHON) -m pip install -e .[dev]

test:
	pytest -q

run-help:
	$(PYTHON) -m penage.app.run_one --help
