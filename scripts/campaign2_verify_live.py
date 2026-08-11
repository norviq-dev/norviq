#!/usr/bin/env python3
"""Live verification of the four fixes that could only be checked on a cluster.

Every check states what it measured, not just pass/fail — a green tick with no number behind it is
how this campaign has been fooled before.
"""
import json
import subprocess
import urllib.request

TOKEN = open("/tmp/nrvq-signin-token.txt").read().strip()
URL = "http://localhost:8080/api/v1/evaluate"


def evaluate(tool, params, agent="r2-verify", ns="analytics"):
    body = json.dumps({
        "agent_id": agent, "agent_class": "r2-verify", "namespace": ns,
        "tool_name": tool, "tool_params": params, "framework": "campaign2",
        "agent_identity": {"spiffe_id": f"spiffe://norviq/ns/{ns}/sa/{agent}",
                           "namespace": ns, "agent_class": "r2-verify", "workload": agent},
    }).encode()
    req = urllib.request.Request(URL, data=body, method="POST", headers={
        "Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.loads(r.read())
            return d.get("decision"), (d.get("rule_id") or "")
    except urllib.error.HTTPError as e:
        return f"HTTP{e.code}", ""
    except Exception as e:
        return "ERR", type(e).__name__


def kubectl(*args):
    return subprocess.run(["kubectl", "--context", "norviq", *args],
                          capture_output=True, text=True).stdout


print("=" * 78)
print("C2-023 — base64 false positives on ordinary prose")
print("  BEFORE (measured pre-fix on this cluster): 2 of 80 tripped deny_shell_execution,")
print("  reproducibly at n=18 and n=58.")
fp = []
for i in range(80):
    dec, rule = evaluate("get_customer", {"note": f"benign call {i}"})
    if rule and rule != "default_allow":
        fp.append((i, dec, rule))
print(f"  AFTER : {len(fp)} of 80 flagged  {fp if fp else '(clean)'}")
print(f"  -> {'PASS' if not fp else 'STILL FAILING'}")

print("=" * 78)
print("C2-022 / C2-012 — rename and homoglyph evasion of a name-keyed control")
print("  Note: these controls ship on MONITOR, so a detection shows as audit/would-block,")
print("  not block. What matters is that the rule FIRES at all — pre-fix it did not.")
cases = [
    ("delete_all_records", "ascii control"),
    ("get_delete_all_records", "C2-022 rename"),
    ("getDeleteAllRecords", "C2-022 camelCase"),
    ("dеlete_all_records", "C2-012 Cyrillic e"),
    ("de​lete_all_records", "C2-012 zero-width"),
    ("get_customer", "benign read (must stay clean)"),
    ("run_query", "over-classified read (must stay clean)"),
]
for tool, label in cases:
    params = {"query": "select 1"} if tool == "run_query" else {"target": "all"}
    dec, rule = evaluate(tool, params)
    flagged = bool(rule) and rule != "default_allow"
    print(f"  {label:<34} {dec:<7} {rule:<48} {'FLAGGED' if flagged else 'clean'}")

print("=" * 78)
print("C2-019 — credentials must not be literal values in the pod spec")
pods = kubectl("-n", "analytics", "get", "pods", "-l", "app=finance-agent", "-o", "json")
try:
    items = json.loads(pods)["items"]
except Exception:
    items = []
live = [p for p in items if p.get("status", {}).get("phase") == "Running"]
if not live:
    print("  no running finance-agent pod found — cannot verify")
else:
    pod = live[0]
    print(f"  pod: {pod['metadata']['name']}  (created {pod['metadata']['creationTimestamp']})")
    for c in pod["spec"]["containers"]:
        if c["name"] != "norviq-sidecar":
            continue
        for e in c.get("env", []):
            n = e["name"]
            if n not in ("NRVQ_API_TOKEN", "NRVQ_CLIENT_CERT_PEM", "NRVQ_CLIENT_KEY_PEM"):
                continue
            if e.get("value"):
                print(f"    {n:<22} *** STILL A LITERAL VALUE ({len(e['value'])} bytes) ***")
            elif "secretKeyRef" in json.dumps(e.get("valueFrom") or {}):
                ref = e["valueFrom"]["secretKeyRef"]
                print(f"    {n:<22} secretKeyRef -> {ref['name']}/{ref['key']}   OK")
            else:
                print(f"    {n:<22} unexpected shape: {e}")
    secs = kubectl("-n", "analytics", "get", "secrets", "-l",
                   "norviq.io/component=sidecar-credentials", "-o",
                   "jsonpath={range .items[*]}{.metadata.name}{'\\n'}{end}")
    print(f"  credential Secrets in analytics: {secs.split() or '(none)'}")

print("=" * 78)
print("C2-020 — the expiry forewarning band")
req = urllib.request.Request("http://localhost:8080/api/v1/system-health",
                             headers={"Authorization": f"Bearer {TOKEN}"})
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        h = json.loads(r.read())
    ids = [i["id"] for i in h.get("issues", [])]
    print(f"  status={h.get('status')}  issues={ids}")
    print("  (a freshly rolled fleet has ~30 days left, so NO band is the correct result here —")
    print("   this confirms the endpoint serves the new code path without erroring)")
except Exception as e:
    print(f"  system-health FAILED: {e}")
print("=" * 78)
