# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A namespace-wide overlay policy change must invalidate the WHOLE namespace's eval cache.

`__baseline__` / `__guardrail__` / `__pack__*` change the effective decision for every agent class in the
namespace. If create/revert only cleared `eval:{ns}:{that-scope}:*`, sibling classes kept serving a stale
cached decision until the short eval TTL expired — e.g. a new `__baseline__` that blocks a tool was still
served as the cached `allow` for ~TTL seconds.

`_invalidate_eval_for_policy_scope` now ALWAYS delegates the actual SCAN/DELETE to
`cache.invalidate_eval_scope(namespace, agent_class)` — cache.py sha256-hashes each key segment there (to
defeat colon-stuffing collisions), so a raw/unhashed pattern built here would silently match nothing. These
tests assert the loader's side of that contract: it passes `agent_class=None` (ns-wide) for a reserved
overlay scope, and the concrete class otherwise — see norviq/engine/policy_loader.py
_invalidate_eval_for_policy_scope.
"""

from __future__ import annotations

import asyncio

from norviq.engine.policy_loader import PolicyLoader


class _FakeCache:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None]] = []

    async def invalidate_eval_scope(self, namespace, agent_class=None):
        self.calls.append((namespace, agent_class))
        return 0


def _invalidate(scope_class: str) -> list[tuple[str, str | None]]:
    cache = _FakeCache()
    loader = PolicyLoader.__new__(PolicyLoader)  # pure method under test; no DB/redis init needed
    loader._cache = cache
    asyncio.run(loader._invalidate_eval_for_policy_scope("scen", scope_class))
    return cache.calls


def test_baseline_change_invalidates_namespace_wide():
    assert _invalidate("__baseline__") == [("scen", None)], "a __baseline__ change must clear EVERY class's eval cache"


def test_guardrail_and_pack_scopes_invalidate_namespace_wide():
    assert _invalidate("__guardrail__") == [("scen", None)]
    assert _invalidate("__pack__") == [("scen", None)]


def test_concrete_class_change_stays_narrowly_scoped():
    assert _invalidate("customer-support") == [("scen", "customer-support")], "a class policy must not over-clear the ns"
