# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Propose a candidate intent from traffic the agent class actually produced.

This closes the loop in §13.6: observe → **propose** → dry-run → apply. Without it, adopting
deny-by-default means an operator writing every rule from memory against a system they only partly
remember, which is how an allowlist ends up both too wide and missing the one tool that matters.

Three things this is NOT:

* **Not enforcement.** The output is a dict. Nothing here writes to `policies`, and applying stays a
  gated operator action — the same reason `IntentDraft` is a table the evaluator never reads.
* **Not a substitute for review.** A proposal describes what the class DID, and "did" is not
  "should". If the recorded window contains an attack, the proposal will happily encode it. The
  dry-run shows coverage; the human decides.
* **Not minimal.** It errs toward tighter rules (narrower destinations, observed tables only), because
  a proposal that is too tight shows up as would-block rows the operator can loosen, whereas one that
  is too loose shows up as nothing at all.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence

# A recipient domain is only proposed as a constraint when the traffic is unambiguous about it.
# Below this, the sample is too thin to claim "this class only ever mails acme.com".
_MIN_CALLS_FOR_DESTINATION_RULE = 3
_MAX_TOOLS_PER_RULE = 40
_MAX_TABLES_PER_RULE = 40
_EMAIL_DOMAIN_RE = re.compile(r"^[^@]+@(.+)$")


def _group_key(payload: dict) -> tuple:
    derived = payload.get("derived") or {}
    mcp = payload.get("mcp") or {}
    return (str(mcp.get("server", "")), str(derived.get("verb", "unknown")))


def _slug(*parts: str) -> str:
    raw = "-".join(p for p in parts if p) or "rule"
    slug = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
    return (slug or "rule")[:63]


def _common_email_domain(payloads: Sequence[dict]) -> str | None:
    """The single recipient domain every observed send used, or None."""
    domains: set[str] = set()
    for payload in payloads:
        derived = payload.get("derived") or {}
        emails = (derived.get("destinations") or {}).get("emails") or []
        if not emails:
            return None  # a send with no recipient we can see: cannot claim a domain constraint
        for address in emails:
            match = _EMAIL_DOMAIN_RE.match(address)
            if not match:
                return None
            domains.add(match.group(1).lower())
    if len(domains) == 1:
        return domains.pop()
    return None


def propose_intent(name: str, agent_class: str, calls: Sequence[dict]) -> dict:
    """Build a candidate intent covering `calls` (policy input documents).

    Rules are grouped by (MCP server, verb) — the two facts that describe an operation without
    depending on what a tool happens to be called. Each rule then carries the observed tool names as
    a registration perimeter, because a name-based allowlist is the only thing that holds against a
    tool nobody has seen before.
    """
    if not calls:
        raise ValueError("cannot propose an intent from zero recorded calls")

    groups: dict[tuple, list] = defaultdict(list)
    for payload in calls:
        groups[_group_key(payload)].append(payload)

    rules = []
    for (server, verb), payloads in sorted(groups.items()):
        derived_list = [(p.get("derived") or {}) for p in payloads]
        tools = sorted({str(p.get("tool_name", "")) for p in payloads if p.get("tool_name")})
        match: dict = {"verb": verb}
        if tools:
            # The perimeter half. Registration-based: an unseen name fails the list rather than
            # being classified into it.
            match["tool_name"] = {"in": tools[:_MAX_TOOLS_PER_RULE]}

        tables = sorted({t for d in derived_list for t in (d.get("sql_tables") or [])})
        if tables:
            match["sql_tables"] = {"subsetOf": tables[:_MAX_TABLES_PER_RULE]}

        if verb == "send":
            domain = _common_email_domain(payloads)
            if domain and len(payloads) >= _MIN_CALLS_FOR_DESTINATION_RULE:
                match["param_paths.to"] = {"matches": rf"^[^@]+@{re.escape(domain)}$"}

        # Tightening that is safe to propose regardless of what was observed: nothing in the recorded
        # window should have been carrying a credential, so requiring its absence cannot break
        # legitimate traffic — and if it does, that is a finding rather than a false positive.
        require = {"data_classes": {"noneOf": ["secret"]}}

        rule: dict = {"id": _slug(server, verb, "-".join(tools[:2])), "match": match, "require": require}
        if server:
            rule["server"] = server
        rules.append(rule)

    # Ids must be unique; collisions are possible once slugs are truncated.
    seen: dict[str, int] = {}
    for rule in rules:
        base = rule["id"]
        if base in seen:
            seen[base] += 1
            rule["id"] = f"{base}-{seen[base]}"[:63]
        else:
            seen[base] = 0

    return {"name": name, "class": agent_class, "call": rules}
