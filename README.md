# Norviq

[![License Compliance](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fnorviq-dev%2Fnorviq.svg?type=shield&issueType=license)](https://app.fossa.com/projects/git%2Bgithub.com%2Fnorviq-dev%2Fnorviq?ref=badge_shield&issueType=license)
[![Vulnerabilities](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fnorviq-dev%2Fnorviq.svg?type=shield&issueType=security)](https://app.fossa.com/projects/git%2Bgithub.com%2Fnorviq-dev%2Fnorviq?ref=badge_shield&issueType=security)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

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

## Local Development (Windows)

Prerequisites:
- PostgreSQL 18 with `norviq` user created
- Memurai (Redis-compatible) running on port 6379
- Python 3.12+, Node.js 20+

Setup:
```powershell
cp .env.local.example .env.local
# Edit .env.local with your local credentials

.\scripts\dev.ps1 setup
```

Run:
```powershell
.\scripts\dev.ps1 api    # Terminal 1
.\scripts\dev.ps1 ui     # Terminal 2
```

## License

Apache 2.0
