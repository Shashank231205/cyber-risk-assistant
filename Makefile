# Development tasks. Run `make help` for the list.
.DEFAULT_GOAL := help
.PHONY: help install setup reference index run test test-fast lint typecheck security format check clean docker-build docker-run

PYTHON ?= python
VENV := .venv
BIN := $(VENV)/bin
ifeq ($(OS),Windows_NT)
	BIN := $(VENV)/Scripts
endif

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install: ## Create the virtual environment and install dependencies
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/python -m pip install -e ".[dev]"

reference: ## Download the CISA KEV and NIST 800-53 snapshots
	$(BIN)/python scripts/fetch_reference_data.py

index: ## Embed the control catalogue and build the retrieval index
	$(BIN)/python scripts/build_index.py
	$(BIN)/python scripts/build_index.py --verify

setup: install reference index ## Full first-time setup

run: ## Start the development server
	$(BIN)/python main.py

test: ## Run the full test suite with coverage
	$(BIN)/python -m pytest

test-fast: ## Run unit tests only, without coverage
	$(BIN)/python -m pytest tests/unit -q --no-cov

lint: ## Check formatting and lint rules
	$(BIN)/python -m ruff check src tests scripts main.py

typecheck: ## Run strict type checking
	$(BIN)/python -m mypy src scripts main.py

security: ## Run security linting and dependency auditing
	$(BIN)/python -m bandit -q -c pyproject.toml -r src scripts
	$(BIN)/python -m pip_audit --strict --ignore-vuln GHSA-4xh5-x5gv-qwph || true

format: ## Apply automatic formatting
	$(BIN)/python -m ruff check --fix src tests scripts main.py
	$(BIN)/python -m black src tests scripts main.py

check: lint typecheck security test ## Run every gate, as CI does
	$(BIN)/python scripts/sync_requirements.py --check

clean: ## Remove caches and generated artefacts
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage coverage.xml
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

docker-build: ## Build the container image
	docker build -t cyber-risk-assistant:local .

docker-run: ## Run the container image
	docker run --rm -p 8000:8000 --env-file .env cyber-risk-assistant:local
