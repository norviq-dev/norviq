# Norviq

Runtime security platform for LLM agent tool calls on Kubernetes.

## What It Does

Norviq sits between LangGraph/LangChain agent reasoning loops and their tools. Every tool call is intercepted, evaluated against OPA/Rego policies scoped to Kubernetes workload identity (SPIFFE/SPIRE SVIDs), and either allowed, blocked, escalated, or audited.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Run tests
make test

# Lint
make lint
```

## License

Apache 2.0
