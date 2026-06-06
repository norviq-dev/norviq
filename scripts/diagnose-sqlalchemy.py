# SPDX-License-Identifier: Apache-2.0
"""Test SQLAlchemy + asyncpg with exact Norviq config."""

import asyncio
import sys
import traceback

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

URL = "postgresql+asyncpg://norviq:norviq_local_dev@127.0.0.1:5433/norviq"


async def try_engine(label, **kwargs):
    print(f"\n=== {label} ===")
    print(f"connect_args: {kwargs.get('connect_args', {})}")
    try:
        engine = create_async_engine(URL, **kwargs, echo=False)
        async with engine.begin() as conn:
            result = await conn.execute(text("SELECT version()"))
            row = result.scalar()
            print(f"SUCCESS: {row[:80]}")
        await engine.dispose()
        return True
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}: {exc}")
        traceback.print_exc()
        return False


async def main():
    # Replicate diagnose-pg.py success cases through SQLAlchemy
    await try_engine("no connect_args")
    await try_engine("connect_args ssl=False", connect_args={"ssl": False})
    await try_engine("connect_args ssl=disable", connect_args={"ssl": "disable"})
    await try_engine("connect_args ssl=prefer", connect_args={"ssl": "prefer"})

    # SQLAlchemy-specific knobs
    await try_engine(
        "ssl=False + statement_cache_size=0",
        connect_args={"ssl": False, "statement_cache_size": 0},
    )
    await try_engine(
        "ssl=prefer + statement_cache_size=0",
        connect_args={"ssl": "prefer", "statement_cache_size": 0},
    )

    # Pool settings
    await try_engine(
        "ssl=False, pool_size=1, max_overflow=0",
        connect_args={"ssl": False},
        pool_size=1,
        max_overflow=0,
    )

    # asyncpg connection class override
    await try_engine(
        "ssl=False + prepared_statement_cache_size=0",
        connect_args={"ssl": False, "prepared_statement_cache_size": 0},
    )
    await try_engine(
        "ssl=False + command_timeout=5",
        connect_args={"ssl": False, "command_timeout": 5},
    )
    await try_engine(
        "ssl=False + command_timeout=30",
        connect_args={"ssl": False, "command_timeout": 30},
    )


if __name__ == "__main__":
    asyncio.run(main())
