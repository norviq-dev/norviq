# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Agent behavioral baseline profile store."""

from __future__ import annotations

import json
from typing import Any

import structlog

from norviq.engine.cache import RedisCache

log = structlog.get_logger()

PROFILE_UPDATE_LUA = """
local key = KEYS[1]
local tool = ARGV[1]
local entropy = tonumber(ARGV[2])
local observed_rpm = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local known_raw = redis.call('HGET', key, 'known_tools')
local baseline_raw = redis.call('HGET', key, 'param_entropy_baseline')
local rpm_raw = redis.call('HGET', key, 'baseline_rpm')
local seen_raw = redis.call('HGET', key, 'tool_seen_counts')
local known = known_raw and cjson.decode(known_raw) or {}
local baseline = baseline_raw and cjson.decode(baseline_raw) or {}
local seen = seen_raw and cjson.decode(seen_raw) or {}
local rpm = rpm_raw and tonumber(rpm_raw) or 10.0
seen[tool] = tonumber(seen[tool] or 0) + 1
if seen[tool] >= 3 then
  local exists = false
  for _,value in ipairs(known) do
    if value == tool then exists = true end
  end
  if not exists and #known < 256 then table.insert(known, tool) end
  table.sort(known)
end
local entry = baseline[tool] or {mean=4.0,std=1.0,count=0,variance=1.0}
local count = tonumber(entry.count or 0) + 1
local old_mean = tonumber(entry.mean or 4.0)
local old_variance = tonumber(entry.variance or 1.0)
local delta = entropy - old_mean
local mean = old_mean + (delta / count)
if mean > (old_mean + 0.25) then mean = old_mean + 0.25 end
if mean < (old_mean - 0.10) then mean = old_mean - 0.10 end
local delta2 = entropy - mean
local variance = old_variance
if count > 1 then
  variance = ((old_variance * (count - 1)) + (delta * delta2)) / count
end
entry.count = count
entry.mean = tonumber(string.format('%.4f', mean))
entry.variance = tonumber(string.format('%.4f', variance))
entry.std = tonumber(string.format('%.4f', math.min(math.max(math.sqrt(variance), 0.2), 3.0)))
baseline[tool] = entry
local next_rpm = (rpm * 0.95) + (observed_rpm * 0.05)
local max_up = rpm * 1.05
if next_rpm > max_up then next_rpm = max_up end
local min_down = rpm * 0.99
if next_rpm < min_down then next_rpm = min_down end
redis.call(
  'HSET',
  key,
  'known_tools',
  cjson.encode(known),
  'param_entropy_baseline',
  cjson.encode(baseline),
  'tool_seen_counts',
  cjson.encode(seen),
  'baseline_rpm',
  string.format('%.4f', math.max(next_rpm, 10.0))
)
redis.call('EXPIRE', key, ttl)
return 1
"""


class AgentProfileStore:
    """Store profile data used for novelty and entropy baselines."""

    WINDOW_SECONDS = 604800

    def __init__(self, cache: RedisCache) -> None:
        """Bind profile store to shared cache."""
        self._cache = cache
        self._update_sha: str | None = None

    async def get_profile(self, spiffe_id: str, agent_class: str) -> dict[str, Any]:
        """Load profile or return defaults."""
        client = self._cache._client()
        if agent_class:
            async with client.pipeline(transaction=False) as pipe:
                await pipe.hgetall(self._key(spiffe_id))
                await pipe.hgetall(f"agent_class:{agent_class}")
                fields, class_row = await pipe.execute()
        else:
            fields = await client.hgetall(self._key(spiffe_id))
            class_row = {}
        profile = self._decode_profile(fields)
        defaults = {
            "known_tools": [],
            "allowed_tools": [],
            "blocked_tools": [],
            "baseline_rpm": 10,
            "param_entropy_baseline": {},
        }
        profile = {**defaults, **profile}
        profile.update(self._decode_class_constraints(class_row))
        profile["agent_class"] = agent_class
        return profile

    async def update_profile(
        self,
        spiffe_id: str,
        tool_name: str,
        param_entropy: float,
        observed_rpm: float,
        decision: str,
    ) -> None:
        """Update known tools and per-tool entropy stats."""
        if decision not in {"allow", "audit"}:
            return
        await self._ensure_script()
        client = self._cache._client()
        call_args = (
            1,
            self._key(spiffe_id),
            tool_name,
            str(param_entropy),
            str(observed_rpm),
            str(self.WINDOW_SECONDS),
        )
        try:
            await client.evalsha(self._update_sha, *call_args)
        except Exception as exc:
            if "NOSCRIPT" not in str(exc):
                raise
            self._update_sha = None
            await self._ensure_script()
            await client.evalsha(self._update_sha, *call_args)
        log.debug("nrvq.engine.trust.profile.updated", spiffe_id=spiffe_id, code="NRVQ-ENG-2048")

    def _key(self, spiffe_id: str) -> str:
        """Build redis key for one agent profile."""
        return f"agent_profile:{spiffe_id}"

    async def _ensure_script(self) -> None:
        """Load Lua update script once per process."""
        if self._update_sha is None:
            self._update_sha = await self._cache._client().script_load(PROFILE_UPDATE_LUA)

    def _decode_class_constraints(self, row: dict[str, str]) -> dict[str, list[str]]:
        """Decode optional class-level allow/block constraints."""
        return {
            "allowed_tools": json.loads(row["allowed_tools"]) if row.get("allowed_tools") else [],
            "blocked_tools": json.loads(row["blocked_tools"]) if row.get("blocked_tools") else [],
        }

    def _decode_profile(self, fields: dict[str, str]) -> dict[str, Any]:
        """Decode profile hash values into typed payload."""
        return {
            "known_tools": json.loads(fields["known_tools"]) if fields.get("known_tools") else [],
            "param_entropy_baseline": json.loads(fields["param_entropy_baseline"])
            if fields.get("param_entropy_baseline")
            else {},
            "baseline_rpm": float(fields["baseline_rpm"]) if fields.get("baseline_rpm") else 10.0,
        }
