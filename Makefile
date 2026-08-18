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

# The five images, every one STAMPED with the commit it was built from.
#
# Two defects this replaces, both found while cutting a release. The webhook line pointed at
# `Dockerfile.webhook`, which does not exist — the real one is `webhook/Dockerfile` with the `webhook`
# directory as its context — so `make docker-build` had never built the webhook at all. And no image
# passed NRVQ_GIT_SHA, so `ENV NRVQ_BUILD_GIT_SHA` kept its `unknown` default and
# `GET /api/v1/version` reported "unknown" in every image built the documented way.
#
# The second one is not cosmetic. The WEBHOOK carries the shipped presets and re-renders every
# namespace's baseline when it rolls, so an install running an older webhook than its API enforces an
# older ruleset while the console describes the newer one. Measured: a false positive fixed in the
# preset kept firing for hours because the webhook image predated the fix, and nothing on any surface
# could have told an operator that — every component reported "unknown".
NRVQ_GIT_SHA ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)

docker-build:
	docker build --build-arg NRVQ_GIT_SHA=$(NRVQ_GIT_SHA) -t norviq/norviq-engine:api-latest       -f Dockerfile.api .
	docker build --build-arg NRVQ_GIT_SHA=$(NRVQ_GIT_SHA) -t norviq/norviq-engine:ui-latest        -f Dockerfile.ui .
	docker build --build-arg NRVQ_GIT_SHA=$(NRVQ_GIT_SHA) -t norviq/norviq-engine:engine-latest    -f Dockerfile.engine .
	docker build --build-arg NRVQ_GIT_SHA=$(NRVQ_GIT_SHA) -t norviq/norviq-engine:webhook-latest   -f webhook/Dockerfile webhook
	docker build --build-arg NRVQ_GIT_SHA=$(NRVQ_GIT_SHA) -t norviq/norviq-engine:bootstrap-latest -f Dockerfile.bootstrap .

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
