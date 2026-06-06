# SPDX-License-Identifier: Apache-2.0
"""Direct asyncpg connection test to diagnose Windows PG 18 issues."""

import asyncio
import sys
import traceback

import asyncpg

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

HOST = "127.0.0.1"
PORT = 5433
USER = "norviq"
PASSWORD = "norviq_local_dev"
DATABASE = "norviq"


async def try_connect(label, **kwargs):
    print(f"\n=== {label} ===")
    print(f"kwargs: {kwargs}")
    try:
        conn = await asyncpg.connect(
            host=HOST,
            port=PORT,
            user=USER,
            password=PASSWORD,
            database=DATABASE,
            **kwargs,
        )
        version = await conn.fetchval("SELECT version()")
        print(f"SUCCESS: {version[:80]}")
        await conn.close()
        return True
    except Exception as exc:
        print(f"FAILED: {type(exc).__name__}: {exc}")
        traceback.print_exc()
        return False


async def main():
    print(f"asyncpg version: {asyncpg.__version__}")
    print(f"Python version: {sys.version}")

    # Try every SSL mode
    await try_connect("Default (no ssl arg)")
    await try_connect("ssl=False", ssl=False)
    await try_connect("ssl='disable'", ssl="disable")
    await try_connect("ssl='require'", ssl="require")
    await try_connect("ssl='prefer'", ssl="prefer")

    # Try with statement_cache_size=0 (sometimes needed on Windows)
    await try_connect("ssl=False, statement_cache_size=0", ssl=False, statement_cache_size=0)


if __name__ == "__main__":
    asyncio.run(main())
