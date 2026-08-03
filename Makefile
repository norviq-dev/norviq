.PHONY: test lint build docker-build kind-up kind-down seed test-unit test-ui test-l3 test-e2e test-all

# --- unit / hermetic ------------------------------------------------------------------------------

# tests/integration and tests/attacks need a live cluster. Running them here would SKIP and XFAIL
# rather than fail — both exit 0 — so `make test` would report success having asked nothing of them.
# They have their own target (test-l3) that asserts a nonzero passed count.
test:
	pytest tests/ --ignore=tests/integration --ignore=tests/attacks -q

test-unit: test

test-ui:
	cd ui && npx vitest run && npx tsc --noEmit && npx eslint src --max-warnings=0 && npm run build

lint:
	ruff check norviq/ tests/

build:
	pip install -e .
	cd webhook && go build -o ../bin/webhook .

docker-build:
	docker build -t norviq/norviq-engine:api-latest       -f Dockerfile.api .
	docker build -t norviq/norviq-engine:ui-latest        -f Dockerfile.ui .
	docker build -t norviq/norviq-engine:engine-latest    -f Dockerfile.engine .
	docker build -t norviq/norviq-engine:webhook-latest   -f Dockerfile.webhook .
	docker build -t norviq/norviq-engine:bootstrap-latest -f Dockerfile.bootstrap .

# --- local cluster --------------------------------------------------------------------------------

## Bring up kind, build and load the five images, install the chart, forward the console, mint a token.
kind-up:
	bash scripts/kind-e2e/00-up.sh

kind-down:
	kind delete cluster --name $${NRVQ_KIND_CLUSTER:-norviq-local}

## Deterministic fixtures: the declared/observed tool tiers, a real drift, and the awkward states the
## console's edge cases are about (withheld description, no schema, name collision, homoglyph).
seed:
	.venv/bin/python scripts/kind-e2e/seed.py

# --- layered test suites --------------------------------------------------------------------------

## L3 — API/middleware against the live cluster. Asserts a NONZERO passed count per suite, because
## both suites skip/xfail into a green exit 0 when the backend is unreachable.
test-l3:
	bash scripts/kind-e2e/l3.sh

## L4 — the console in a browser against the live cluster.
test-e2e:
	bash scripts/e2e.sh

## Everything, in the order that fails fastest: hermetic first, cluster last.
test-all: test-unit test-ui test-l3 test-e2e
	@echo "\n✓ L1 (pytest) · L2 (vitest/tsc/eslint/build) · L3 (integration+attacks) · L4 (playwright)"
