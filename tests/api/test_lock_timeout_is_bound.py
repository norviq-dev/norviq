# SPDX-License-Identifier: Apache-2.0
"""The admin trust writes set a transaction-local lock_timeout. It is sent as a BOUND parameter through
set_config(..., is_local => true): the same effect as `SET LOCAL lock_timeout = '<ms>ms'`, without building
SQL text from a value. Checked against a real Postgres: the setting holds inside the transaction and is
gone after it."""
from __future__ import annotations

import os

import pytest
from sqlalchemy import text

from norviq.api.db import session as db_session
from norviq.api.routers import agents as agents_mod
from norviq.config import settings


@pytest.fixture
async def engine():
    pg_url = (os.getenv("NRVQ_PG_URL") or "").strip().strip("\"'")
    if not pg_url:
        pytest.fail("NRVQ_PG_URL must be set for PostgreSQL integration tests")
    old = settings.pg_url
    settings.pg_url = pg_url
    await db_session.init_db()
    try:
        yield db_session._engine
    finally:
        await db_session._engine.dispose()
        settings.pg_url = old


def test_the_statement_carries_no_interpolated_value() -> None:
    clause = agents_mod._set_local_lock_timeout_sql(1234)
    assert "1234" not in str(clause), "the value must be a bind parameter, not part of the SQL text"
    assert clause.compile().params == {"v": "1234ms"}


async def test_the_lock_timeout_is_transaction_local(engine) -> None:
    async with engine.connect() as conn:
        before = (await conn.execute(text("SHOW lock_timeout"))).scalar()
        await conn.rollback()  # end the autobegun read so the explicit transaction below is the only one
        async with conn.begin():
            await conn.execute(agents_mod._set_local_lock_timeout_sql(4321))
            assert (await conn.execute(text("SHOW lock_timeout"))).scalar() == "4321ms"
        assert before != "4321ms"
        assert (await conn.execute(text("SHOW lock_timeout"))).scalar() == before
