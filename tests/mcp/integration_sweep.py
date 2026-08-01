#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Live integration sweep: does MCP traffic break any EXISTING console/API surface?

Run against a live Norviq API (in-cluster). This is the regression test that matters for a feature
that adds a new *shape* of data to a shared store: MCP audit rows carry `framework="mcp"`, tool names
containing a slash (`resources/read`, `sampling/createMessage`), and a `payload.mcp` object no
existing reader has ever seen. Every one of those flows into surfaces that were written before MCP
existed — the audit log, the agent views, the threat/coverage roll-ups, the graphs, compliance.

Method:
  1. Snapshot every read surface BEFORE any MCP traffic.
  2. Generate real MCP decisions through /evaluate (allow, block, escalate; slashed tool names;
     mcp context attached).
  3. Re-read every surface and assert it still answers, still parses, and now reflects the traffic.

A 200 alone is not the assertion — each check states what it expects to be TRUE of the payload.

    python -m tests.mcp.integration_sweep <api_url> <admin_token> <service_token>
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

NS = "agents"
AGENT_CLASS = "mcp-agent"
SPIFFE = f"spiffe://norviq/ns/{NS}/sa/default"

# Every read surface a console user can reach that could plausibly see MCP rows. Deliberately
# includes surfaces that SHOULDN'T change (policies, settings) — a feature that perturbs those is
# a bug, and the sweep should notice.
READ_SURFACES = [
    ("audit_records", "/api/v1/audit/records?limit=50&range=1h"),
    ("audit_records_mcp", "/api/v1/audit/records?limit=50&range=1h&framework=mcp"),
    ("audit_stats", "/api/v1/audit/stats?range=1h"),
    ("audit_volume", "/api/v1/audit/volume?range=1h"),
    ("audit_top_blocked", "/api/v1/audit/top-blocked?range=1h"),
    ("audit_export", "/api/v1/audit/export?range=1h&limit=25"),
    ("agents", "/api/v1/agents"),
    ("agent_tool_usage", f"/api/v1/agents/{SPIFFE}/tool-usage"),
    ("agent_trust_history", f"/api/v1/agents/{SPIFFE}/trust-history"),
    ("threats_tool_verbs", f"/api/v1/threats/tool-verbs?ns={NS}"),
    ("threats_attack_paths", f"/api/v1/threats/attack-paths?ns={NS}"),
    ("coverage_by_category", f"/api/v1/coverage-by-category?namespace={NS}"),
    ("mitre_coverage", f"/api/v1/mitre/coverage?namespace={NS}"),
    ("compliance_owasp", f"/api/v1/compliance/owasp/coverage?namespace={NS}"),
    ("compliance_atlas", f"/api/v1/compliance/atlas/coverage?namespace={NS}"),
    ("asset_graph", f"/api/v1/asset-graph?namespace={NS}"),
    ("graph_summary", "/api/v1/graph/summary"),
    ("graph_analysis", "/api/v1/graph/analysis"),
    ("policies", "/api/v1/policies"),
    ("system_health", "/api/v1/system-health"),
    ("search", "/api/v1/search?q=send"),
    ("mcp_servers", f"/api/v1/mcp/servers?namespace={NS}"),
    ("mcp_pins", f"/api/v1/mcp/pins?namespace={NS}"),
]

# The MCP traffic to generate. Covers: slashed tool names, all four decisions, and the mcp context.
MCP_CALLS = [
    ("search_docs", {"query": "quarterly"}, "github", "allow"),
    ("read_file", {"path": "/workspace/a.md"}, "filesystem", "allow"),
    ("delete_records", {"table": "users"}, "postgres", "block"),
    ("send_email", {"to": "x@attacker.example", "body": "k"}, "smtp", "block"),
    ("resources/read", {"uri": "file:///workspace/summary.md"}, "filesystem", "allow"),
    ("sampling/createMessage", {"message_count": 1, "max_tokens": 4096}, "github", "any"),
    ("write_record", {"table": "notes", "value": "x"}, "postgres", "any"),
]


def _req(url: str, token: str, method: str = "GET", body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        **({"Content-Type": "application/json"} if data else {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            try:
                return resp.status, json.loads(raw)
            except ValueError:
                return resp.status, raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")[:400]
    except Exception as exc:  # noqa: BLE001 - the sweep reports, it does not crash
        return 0, f"{type(exc).__name__}: {exc}"


def _rows(payload) -> list:
    """Normalise the two shapes the read surfaces use (bare list / {items|records|...})."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("items", "records", "rows", "data", "results", "agents", "nodes"):
            if isinstance(payload.get(key), list):
                return payload[key]
    return []


def main() -> int:
    api, admin, service = sys.argv[1], sys.argv[2], sys.argv[3]
    failures: list[str] = []
    notes: list[str] = []

    # ---------------------------------------------------------------- 1. before
    print("== BEFORE: every read surface answers ==")
    before: dict[str, object] = {}
    for name, path in READ_SURFACES:
        status, payload = _req(api + path, admin)
        before[name] = payload
        ok = status == 200
        print(f"  {'ok ' if ok else 'FAIL'} {status:3} {name}")
        if not ok:
            failures.append(f"BEFORE {name}: {status} {str(payload)[:160]}")

    # ---------------------------------------------------------------- 2. traffic
    print("\n== generating MCP traffic through /evaluate ==")
    decisions: dict[str, str] = {}
    for tool, params, server, expected in MCP_CALLS:
        body = {
            "tool_name": tool,
            "tool_params": params,
            "agent_identity": {"spiffe_id": SPIFFE, "namespace": NS, "agent_class": AGENT_CLASS},
            "session_id": "sweep",
            "framework": "mcp",
            # The new additive field. If any existing consumer chokes on it, the surfaces below break.
            "mcp": {
                "server": server, "transport": "stdio", "surface": "tools/call",
                "pin_status": "pinned", "scan_severity": "none",
                "definition_seen": True, "tool_digest": "deadbeefdeadbeef",
            },
        }
        status, payload = _req(api + "/api/v1/evaluate", service, "POST", body)
        if status != 200:
            failures.append(f"evaluate {tool}: {status} {str(payload)[:200]}")
            print(f"  FAIL {status} {tool}")
            continue
        got = payload.get("decision")
        decisions[tool] = got
        mark = "ok " if (expected == "any" or got == expected) else "FAIL"
        if mark == "FAIL":
            failures.append(f"evaluate {tool}: expected {expected}, got {got}")
        print(f"  {mark} {tool:26} -> {got:8} ({payload.get('rule_id')})")

    # ---------------------------------------------------------------- 3. after
    print("\n== AFTER: every read surface still answers ==")
    after: dict[str, object] = {}
    for name, path in READ_SURFACES:
        status, payload = _req(api + path, admin)
        after[name] = payload
        ok = status == 200
        print(f"  {'ok ' if ok else 'FAIL'} {status:3} {name}")
        if not ok:
            failures.append(f"AFTER {name}: {status} {str(payload)[:160]}")

    # ---------------------------------------------------------------- 4. real assertions
    print("\n== effect assertions (not just 200s) ==")

    def check(label: str, condition: bool, detail: str = "") -> None:
        print(f"  {'ok ' if condition else 'FAIL'} {label}{(' — ' + detail) if detail and not condition else ''}")
        if not condition:
            failures.append(f"{label}: {detail}")

    mcp_rows = _rows(after.get("audit_records_mcp"))
    check("MCP calls produced audit rows", len(mcp_rows) >= len(MCP_CALLS),
          f"expected >={len(MCP_CALLS)}, got {len(mcp_rows)}")
    check("every MCP audit row is attributed framework=mcp",
          all(r.get("framework") == "mcp" for r in mcp_rows) if mcp_rows else False)

    slashed = [r for r in mcp_rows if "/" in str(r.get("tool_name", ""))]
    check("slashed tool names survive the audit round trip", bool(slashed),
          "no resources/read or sampling/createMessage row found")

    blocked = [r for r in mcp_rows if r.get("decision") == "block"]
    check("blocked MCP calls are recorded as blocks", len(blocked) >= 2,
          f"only {len(blocked)} block rows")
    check("blocks carry the enforcing rule_id", all(r.get("rule_id") for r in blocked) if blocked else False)

    # The framework filter must not leak non-MCP rows, and must not hide MCP ones.
    all_rows = _rows(after.get("audit_records"))
    check("the unfiltered audit log includes the MCP rows",
          any(r.get("framework") == "mcp" for r in all_rows))

    # Surfaces that must NOT be perturbed by MCP traffic.
    # The invariant is that MCP traffic must not CREATE, MODIFY or DELETE a policy — not that the
    # payload is byte-identical. `matches` is a live evaluation counter and moves with any traffic at
    # all, MCP or otherwise; asserting on it would be asserting the engine does not count.
    def _policy_identity(payload) -> list:
        return sorted(
            (r.get("namespace"), r.get("agent_class"), r.get("current_version"),
             r.get("priority"), r.get("enforcement_mode"), r.get("rego_length"))
            for r in _rows(payload)
        )
    check("MCP traffic creates/modifies/deletes no policy",
          _policy_identity(before.get("policies")) == _policy_identity(after.get("policies")),
          f"{_policy_identity(before.get('policies'))} -> {_policy_identity(after.get('policies'))}")
    check("the policy that governed the MCP calls counted them",
          any(r.get("matches", 0) > 0 for r in _rows(after.get("policies"))))

    # Agent views must attribute the traffic to the agent.
    usage = _rows(after.get("agent_tool_usage")) or after.get("agent_tool_usage")
    check("agent tool-usage reflects MCP tools", bool(usage), "empty tool-usage after MCP traffic")

    # The verb classifier must not choke on slashed names — the console's Threats screen reads this.
    verbs = after.get("threats_tool_verbs")
    check("threats/tool-verbs still parses", isinstance(verbs, dict) or isinstance(verbs, list))

    # ---------------------------------------------------------------- 5. summary
    print("\n" + "=" * 72)
    if notes:
        for n in notes:
            print("note:", n)
    if failures:
        print(f"FAILED — {len(failures)} problem(s):")
        for f in failures:
            print("  -", f)
        return 1
    print(f"PASSED — {len(READ_SURFACES)} read surfaces x2, {len(MCP_CALLS)} MCP decisions, all effect checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
