.PHONY: help setup install run-local run-local-backend run-local-frontend run-docker stop clean test

DOCKER_COMPOSE := $(shell command -v docker-compose 2> /dev/null || echo "docker compose")

help: ## Show all available commands (default)
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## First-time setup: copy .env if missing and install dependencies
	@if [ ! -f .env ]; then cp .env.example .env && echo "Created .env from .env.example"; fi
	$(MAKE) install

install: ## Install backend and frontend dependencies
	@echo "Installing backend Python dependencies..."
	@cd backend && python3 -m pip install -r requirements.txt
	@echo "Installing frontend dependencies..."
	@cd frontend && npm ci

run-local: ## Run backend (port 8003) and frontend (port 3003) locally
	@echo "Starting S-Gates backend (8003) and frontend (3003)..."
	@(trap 'kill 0' SIGINT; set -a; . ./.env; set +a; (cd backend && APP_ENV=development DATABASE_URL=sqlite:///./s_gates_local.db EVIDENCE_VAULT_DIR=./evidence_vault uvicorn app.main:app --reload --port 8003) & (cd frontend && BACKEND_INTERNAL_URL=http://127.0.0.1:8003 npm run dev -- -p 3003) & wait)

run-local-backend: ## Run backend only (port 8003)
	@set -a; . .env; set +a; cd backend && APP_ENV=development DATABASE_URL=sqlite:///./s_gates_local.db EVIDENCE_VAULT_DIR=./evidence_vault uvicorn app.main:app --reload --port 8003

run-local-frontend: ## Run frontend only (port 3003)
	@cd frontend && BACKEND_INTERNAL_URL=http://127.0.0.1:8003 npm run dev -- -p 3003

run-docker: ## Run services in Docker Compose
	@echo "Building and starting S-Gates containers using $(DOCKER_COMPOSE)..."
	$(DOCKER_COMPOSE) up --build -d

stop: ## Stop Docker containers
	$(DOCKER_COMPOSE) stop

clean: ## Stop containers and remove volumes
	$(DOCKER_COMPOSE) down -v

test: ## Run unit and integration tests inside backend container (or locally)
	@if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^s_gates_backend$$'; then \
		docker exec s_gates_backend python -m pytest tests/ -v; \
	else \
		cd backend && python3 -m pytest tests/ -v; \
	fi
