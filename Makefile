SHELL := /bin/bash

.PHONY: help build test check serve docker-build docker-build-frontend docker-build-prod docker-run deploy clean

GCP_PROJECT_ID ?= $(shell gcloud config get-value project 2>/dev/null)
GCP_REGION ?= europe-west1
CLOUD_RUN_SVC ?= ai-supply-chain-trust-rust
AR_REPO ?= aibim
IMAGE_TAG ?= latest
IMAGE_URI := $(GCP_REGION)-docker.pkg.dev/$(GCP_PROJECT_ID)/$(AR_REPO)/$(CLOUD_RUN_SVC):$(IMAGE_TAG)
RUST_PORT ?= 8000
BACKEND_DIR := backend
RUST_BIN := $(BACKEND_DIR)/target/release/ai-supply-chain-trust

help:
	@echo "AI Supply Chain Trust (Rust)"
	@echo ""
	@echo "  make build         Build release binary"
	@echo "  make check         Check compilation (fast)"
	@echo "  make test          Run all tests"
	@echo "  make serve         Start server on :$(RUST_PORT)"
	@echo "  make docker-build  Build Docker image"
	@echo "  make docker-build-frontend  Build frontend image"
	@echo "  make docker-build-prod  Build backend+frontend compose images"
	@echo "  make docker-run    Run Docker container"
	@echo "  make deploy        Deploy to Cloud Run via Cloud Build"
	@echo "  make clean         Clean build artifacts"

build:
	cd $(BACKEND_DIR) && cargo build --release -p ai-supply-chain-trust

check:
	cd $(BACKEND_DIR) && cargo check --workspace

test:
	cd $(BACKEND_DIR) && cargo test --workspace

serve: build
	GITHUB_TOKEN=$(GITHUB_TOKEN_SECRET) $(RUST_BIN) serve --port $(RUST_PORT)

docker-build:
	docker build -f backend/Dockerfile -t ai-supply-chain-trust:$(IMAGE_TAG) backend

docker-build-frontend:
	docker build -f frontend/Dockerfile -t ai-supply-chain-trust-frontend:$(IMAGE_TAG) frontend

docker-build-prod:
	docker compose -f .github/deploy/production/docker-compose.prod.yml build backend frontend

docker-run:
	docker run -p $(RUST_PORT):8000 -e GITHUB_TOKEN=$(GITHUB_TOKEN_SECRET) ai-supply-chain-trust:$(IMAGE_TAG)

deploy:
	gcloud builds submit --config cloudbuild-rust.yaml \
		--substitutions=_REGION=$(GCP_REGION),_AR_REPO=$(AR_REPO),_SERVICE=$(CLOUD_RUN_SVC),_TAG=$(IMAGE_TAG)

clean:
	cd $(BACKEND_DIR) && cargo clean
	rm -rf .cache/ai-supply-chain-trust
