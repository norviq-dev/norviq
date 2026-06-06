#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Seed local PostgreSQL with the comprehensive Rego policy."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.policy_loader import PolicyLoader


def _load_env_file(path: Path) -> None:
    """Load simple KEY=VALUE pairs into process environment."""
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def _normalize_local_pg_url() -> None:
    """Build NRVQ_PG_URL from NRVQ_DB_* for local Windows setup."""
    host = os.getenv("NRVQ_DB_HOST", "127.0.0.1")
    port = os.getenv("NRVQ_DB_PORT", "5433")
    user = os.getenv("NRVQ_DB_USER", "norviq")
    password = os.getenv("NRVQ_DB_PASSWORD", "")
    db_name = os.getenv("NRVQ_DB_NAME", "norviq")
    os.environ["NRVQ_PG_URL"] = f"postgresql://{user}:{password}@{host}:{port}/{db_name}?sslmode=disable"


async def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    _load_env_file(repo_root / ".env.local")
    _normalize_local_pg_url()

    rego_path = repo_root / "comprehensive.rego"
    if not rego_path.exists():
        print(f"comprehensive.rego not found at {rego_path}")
        raise SystemExit(1)

    rego = rego_path.read_text(encoding="utf-8")
    print(f"Seeding comprehensive policy ({len(rego)} chars)...")

    cache = RedisCache()
    await cache.connect()
    evaluator = OPAEvaluator(cache)
    loader = PolicyLoader(cache, evaluator)
    try:
        await loader.create(
            namespace="default",
            agent_class="customer-support",
            rego_source=rego,
            enforcement_mode="block",
            saved_by="local-seed",
            priority=700,
        )
    finally:
        await loader.close()
        await cache.close()

    print("Seeded.")


if __name__ == "__main__":
    asyncio.run(main())
