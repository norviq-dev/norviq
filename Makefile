.PHONY: test lint build docker-build

test:
	pytest tests/ -v --tb=short

lint:
	ruff check norviq/ tests/

build:
	pip install -e .
	cd norviq/webhook && go build -o ../../bin/webhook .
	cd norviq/cli && go build -o ../../bin/norviq-cli .

docker-build:
	podman build -t norviq-engine -f Dockerfile.engine .
	podman build -t norviq-api -f Dockerfile.api .
	podman build -t norviq-sidecar -f Dockerfile.sidecar .
