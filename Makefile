.DEFAULT_GOAL := help
PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
COMPOSE ?= docker compose

.PHONY: help install test lint format demo demo-down demo-local demo-local-down report build clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install: ## Create a virtualenv and install the package with dev tools
	$(PY) -m venv $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"
	$(BIN)/pre-commit install || true

test: ## Run the test suite with coverage
	$(BIN)/pytest

lint: ## Run ruff (lint + format check) and mypy --strict
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .
	$(BIN)/mypy

format: ## Auto-format and auto-fix lint issues
	$(BIN)/ruff check --fix .
	$(BIN)/ruff format .

demo: ## Start the demo lab (Docker) and run both modes against it
	$(COMPOSE) up -d --build legacy-site new-site
	$(PY) scripts/wait_for.py http://127.0.0.1:8080/ http://127.0.0.1:8081/
	$(BIN)/sitecheckup audit http://127.0.0.1:8080 --i-have-permission
	$(BIN)/sitecheckup compare http://127.0.0.1:8080 http://127.0.0.1:8081 --i-have-permission

demo-down: ## Stop the Docker demo lab
	$(COMPOSE) --profile wordpress down -v

demo-local: ## Start the demo lab with a locally installed nginx (no Docker)
	scripts/demo_local.sh start

demo-local-down: ## Stop the nginx-based demo lab
	scripts/demo_local.sh stop

report: ## Regenerate docs/examples/ from a running demo lab
	$(BIN)/python scripts/generate_examples.py

build: ## Build sdist + wheel
	$(BIN)/python -m build

clean: ## Remove build and cache artefacts
	rm -rf build dist .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov src/*.egg-info
