# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The three upstream MCP servers the chatbot demo governs: kb, crm and ops.

WHY THREE SERVERS AND NOT ONE WITH NINE TOOLS. Norviq attributes a decision to a `server_id`, and
one firewall sidecar fronts one upstream. Splitting the surface by blast radius is what lets a
policy say "kb is fine, crm is fine, ops is not" as a statement about a SERVER rather than as nine
per-tool exceptions that drift apart the moment someone adds a tenth tool. Collapsing these into one
process would still work over the wire and would quietly destroy that property.

WHY THERE IS NO NORVIQ CODE IN HERE. These are ordinary MCP servers with no idea they are being
policed; the firewall sits in the CLIENT's pod. If governance depended on the server cooperating,
the demo would be proving the wrong thing -- a real third-party MCP server will not import our SDK.

WHY /_calls EXISTS. A blocked call and an executed-then-rewritten call can look identical to the
client: both come back as a JSON-RPC body the caller did not want. The response body therefore
cannot prove non-execution. This ledger can, because it is written from inside the tool body -- a
hit here means the code ran, and an empty ledger after an attack means the request never got past
the firewall. It is a test oracle, not a feature; nothing in the product reads it.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

# The contract's tool surface, spelled out once. Every one of these strings is load-bearing in two
# places that fail differently: the Rego keys on the tool name, so a typo turns a BLOCK into a
# silent ALLOW, and the attack scenarios key on it too, so the same typo turns a failing test green.
# `verify_catalog` asserts what the server actually advertises against this table at startup, which
# is the only moment a typo is still cheap.
CONTRACT_TOOLS: dict[str, frozenset[str]] = {
    "kb": frozenset({"search_kb", "get_article"}),
    "crm": frozenset({"get_customer", "get_order", "update_ticket"}),
    "ops": frozenset({"execute_sql", "delete_record", "send_email", "export_customers"}),
}
SERVER_IDS: tuple[str, ...] = ("kb", "crm", "ops")

_ALL_TOOLS: frozenset[str] = frozenset().union(*CONTRACT_TOOLS.values())

# ---------------------------------------------------------------------------- canned data
#
# Deliberately identical to examples/chatbot/tools.py -- same ids, same fields, same wording. The
# demo tells one story twice (local Python tools, then real MCP servers) and the only difference a
# viewer should be able to see is WHERE the call was adjudicated. Different sample data would read
# as "the MCP path returns something else", which is precisely the wrong takeaway.

# Insertion order is part of the behaviour, not presentation: `search_kb` returns the FIRST key
# contained in the query, exactly as tools.py does. Reordering these silently changes the answer to
# any question that mentions two topics ("can I return this, and what does shipping cost?").
_KB: dict[str, str] = {
    "refund policy": "Refunds are available within 30 days of purchase.",
    "shipping": "Standard shipping takes 5-7 business days.",
    "warranty": "All products come with a 1-year warranty.",
    "returns": "Return items in original packaging within 30 days.",
}

# Articles are the same four answers with an id and a title, so `get_article` cannot contradict
# `search_kb` -- there is one copy of each sentence. tools.py has no equivalent tool, so there is
# nothing here for the two demos to disagree about.
_ARTICLES: dict[str, dict[str, str]] = {
    "KB-001": {"id": "KB-001", "title": "Refund policy", "body": _KB["refund policy"]},
    "KB-002": {"id": "KB-002", "title": "Shipping times", "body": _KB["shipping"]},
    "KB-003": {"id": "KB-003", "title": "Warranty coverage", "body": _KB["warranty"]},
    "KB-004": {"id": "KB-004", "title": "Returns process", "body": _KB["returns"]},
}

_CUSTOMERS: dict[str, dict[str, str]] = {
    "C001": {"name": "Alice Johnson", "email": "alice@example.com", "tier": "gold"},
    "C002": {"name": "Bob Smith", "email": "bob@example.com", "tier": "silver"},
    "C003": {"name": "Carol Davis", "email": "carol@example.com", "tier": "bronze"},
}

_ORDERS: dict[str, dict[str, Any]] = {
    "ORD-001": {"customer": "C001", "product": "Laptop Pro", "status": "shipped", "amount": 1299.99},
    "ORD-002": {"customer": "C002", "product": "ThinkPad X1", "status": "delivered", "amount": 1499.99},
    "ORD-003": {"customer": "C003", "product": "Monitor 27", "status": "processing", "amount": 449.99},
}

# ---------------------------------------------------------------------------- invocation ledger

# Process-local on purpose: one server per pod, and a shared store would let one replica's history
# answer for another's. A test that needs a clean slate calls DELETE /_calls first.
_CALLS: list[dict[str, str]] = []

# Bounded so a long-lived demo pod cannot be walked into unbounded growth by anyone who can reach a
# tool. The oldest entries are dropped, so `count` is "entries currently held", not "calls ever" --
# reset before the assertion you care about rather than reasoning about a running total.
_MAX_CALLS = 512


def _record(tool: str, args: dict[str, Any]) -> None:
    """Note from inside a tool body that the tool actually ran.

    The tempting simplification is one HTTP middleware on /mcp instead of nine call sites. Do not:
    middleware counts requests that ARRIVED, and the entire question this endpoint answers is
    whether a request that arrived went on to EXECUTE. Norviq can answer a tools/call itself, and
    can rewrite a response after the fact; both leave the HTTP layer looking identical to a real
    invocation. Only a write from inside the function body distinguishes them.
    """
    if tool not in _ALL_TOOLS:
        # A mistyped name here would file real invocations under a tool nobody asserts on, so the
        # "nothing executed" check would pass while the sink had in fact run. Fail loudly instead;
        # the exception surfaces as a tool error on the very first call.
        raise RuntimeError(f"demo_mcp: refusing to record unknown tool {tool!r}")
    # A DIGEST, never the arguments. This endpoint is unauthenticated and exists to be scraped by
    # tests, so a raw dump would put customer records into it -- and would mirror back verbatim any
    # injection payload a red-team scenario planted in an argument, turning a debug aid into a
    # second delivery channel for the thing under test. The digest is reproducible by a test:
    # sha256 of the arguments as canonical JSON (sorted keys, no spaces), first 16 hex characters.
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    _CALLS.append(
        {
            "tool": tool,
            "at": datetime.now(timezone.utc).isoformat(),
            "args_digest": hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16],
        }
    )
    del _CALLS[:-_MAX_CALLS]


# ---------------------------------------------------------------------------- tool registration
#
# Every tool below takes its description from the `description=` kwarg rather than from a docstring,
# and that is not a style preference. `Tool.from_function` assigns `fn.__doc__` VERBATIM -- there is
# no dedent -- so an indented multi-line docstring ships its leading whitespace into tools/list, and
# from there into Norviq's Gate A scanner and the policy UI that renders the catalog. These strings
# are an interface, so they are written as one.
#
# They are also honest. Gate A is supposed to be able to notice that `execute_sql` is unrestricted,
# and it can only do that if the server says so. The attack scenarios that put hostile text in a
# description live elsewhere by design -- planting one here would make every run of the demo an
# attack and there would be no baseline to compare against.


def _register_kb(mcp: FastMCP) -> None:
    @mcp.tool(
        description="Search the customer-support knowledge base for product, shipping, warranty and "
        "returns information. Read-only; returns the matching answer as plain text.",
    )
    def search_kb(
        query: Annotated[str, Field(description="Words to search for, e.g. 'refund policy' or 'shipping'.")],
    ) -> str:
        _record("search_kb", {"query": query})
        lowered = query.lower()
        for key, value in _KB.items():
            if key in lowered:
                return value
        return f"No results found for: {query}"

    @mcp.tool(
        description="Retrieve the full text of one knowledge-base article by its id. Read-only; ids "
        "look like 'KB-001'.",
    )
    def get_article(
        article_id: Annotated[str, Field(description="Knowledge-base article id, e.g. 'KB-001'.")],
    ) -> str:
        _record("get_article", {"article_id": article_id})
        return str(_ARTICLES.get(article_id, "Article not found"))


def _register_crm(mcp: FastMCP) -> None:
    @mcp.tool(
        description="Look up a customer record -- name, email address and support tier -- by customer id. "
        "Read-only.",
    )
    def get_customer(
        customer_id: Annotated[str, Field(description="Customer id, e.g. 'C001'.")],
    ) -> str:
        _record("get_customer", {"customer_id": customer_id})
        return str(_CUSTOMERS.get(customer_id, "Customer not found"))

    @mcp.tool(
        description="Look up an order -- customer, product, fulfilment status and amount -- by order id. "
        "Read-only.",
    )
    def get_order(
        order_id: Annotated[str, Field(description="Order id, e.g. 'ORD-001'.")],
    ) -> str:
        _record("get_order", {"order_id": order_id})
        return str(_ORDERS.get(order_id, "Order not found"))

    @mcp.tool(
        description="Set the status of an existing support ticket. This writes to the ticketing system; "
        "usual statuses are open, pending, resolved and closed.",
    )
    def update_ticket(
        ticket_id: Annotated[str, Field(description="Support ticket id, e.g. 'TKT-1043'.")],
        status: Annotated[str, Field(description="New ticket status, e.g. 'resolved'.")],
    ) -> str:
        _record("update_ticket", {"ticket_id": ticket_id, "status": status})
        # "[SIMULATED]" even though this one is benign: nothing is persisted anywhere, and a demo
        # that answered "Ticket updated." would be claiming a side effect it never had.
        return f"[SIMULATED] Ticket {ticket_id} set to {status}"


def _register_ops(mcp: FastMCP) -> None:
    # The dangerous sinks. Each returns a "[SIMULATED] ..." string that ECHOES its arguments, which
    # is deliberate and worth keeping: the echo is what makes the response an injection-reflection
    # path, so Norviq's output-side mediation has something real to act on. Sanitising the echo here
    # would move the defence into the very component the demo assumes is untrusted.

    @mcp.tool(
        description="Run a SQL statement against the support database and return the result. The statement "
        "is not restricted -- it may read or modify any table, including customer records.",
    )
    def execute_sql(
        query: Annotated[str, Field(description="SQL statement to execute.")],
    ) -> str:
        _record("execute_sql", {"query": query})
        return f"[SIMULATED] SQL executed: {query}"

    @mcp.tool(
        description="Permanently delete one row from a table in the support database. Not reversible and "
        "not undone by a later ticket update.",
    )
    def delete_record(
        table: Annotated[str, Field(description="Database table name, e.g. 'customers'.")],
        record_id: Annotated[str, Field(description="Primary key of the row to delete.")],
    ) -> str:
        _record("delete_record", {"table": table, "record_id": record_id})
        return f"[SIMULATED] Deleted {record_id} from {table}"

    @mcp.tool(
        description="Send an email from the support mailbox to any recipient address. Delivery is external "
        "and cannot be recalled.",
    )
    def send_email(
        to: Annotated[str, Field(description="Recipient email address.")],
        subject: Annotated[str, Field(description="Email subject line.")],
        body: Annotated[str, Field(description="Email body text.")],
    ) -> str:
        # `body` is recorded (as part of the digest) but never echoed. It is the argument most
        # likely to carry exfiltrated data, and the demo does not need it in the transcript to make
        # its point -- the recipient address is what a policy adjudicates.
        _record("send_email", {"to": to, "subject": subject, "body": body})
        return f"[SIMULATED] Email sent to {to}: {subject}"

    @mcp.tool(
        description="Export the entire customer table to an external destination such as an object-store "
        "bucket or a URL. Bulk egress of personal data.",
    )
    def export_customers(
        destination: Annotated[str, Field(description="Where to write the export, e.g. 's3://bucket/path'.")],
    ) -> str:
        _record("export_customers", {"destination": destination})
        return f"[SIMULATED] Exported {len(_CUSTOMERS)} customer records to {destination}"


_REGISTRARS: dict[str, Callable[[FastMCP], None]] = {
    "kb": _register_kb,
    "crm": _register_crm,
    "ops": _register_ops,
}

_INSTRUCTIONS: dict[str, str] = {
    "kb": "Read-only knowledge-base lookups for the customer-support desk.",
    "crm": "Customer, order and support-ticket records for the customer-support desk.",
    "ops": "Back-office operations for the support desk: database access, outbound email and bulk export.",
}


# ---------------------------------------------------------------------------- diagnostics routes


def _register_diagnostics(mcp: FastMCP, server_id: str) -> None:
    """Attach /health and /_calls to the same app, and therefore the same port, as /mcp.

    Same port matters: the firewall sidecar forwards only /mcp, so a second listener would be
    reachable by a path the demo's own traffic never takes, and a probe against it would prove
    nothing about the port that actually serves tools.
    """

    @mcp.custom_route("/health", methods=["GET"])
    async def health(request: Request) -> Response:
        del request
        return JSONResponse({"status": "ok", "server": server_id})

    @mcp.custom_route("/_calls", methods=["GET", "DELETE"])
    async def calls(request: Request) -> Response:
        if request.method == "DELETE":
            _CALLS.clear()
            return JSONResponse({"calls": [], "count": 0})
        # A copy: the list is mutated by tools running on the same event loop, and handing out the
        # live object would let a concurrent invocation change what is being serialised.
        snapshot = list(_CALLS)
        return JSONResponse({"calls": snapshot, "count": len(snapshot)})


# ---------------------------------------------------------------------------- construction


def build_server(
    server_id: str,
    # Binding all interfaces is required, not lazy: the Service routes pod-to-pod traffic here and
    # kubelet probes /health on the pod IP. FastMCP's 127.0.0.1 default would fail both, and would
    # also silently enable its DNS-rebinding host allowlist, which only knows about localhost.
    host: str = "0.0.0.0",  # nosec B104 - reached from other pods via a Service; see above
    port: int = 8080,
) -> FastMCP:
    """Build the FastMCP app for one server id. Raises ValueError for an unknown id."""
    if server_id not in _REGISTRARS:
        raise ValueError(f"unknown server id {server_id!r}; expected one of {', '.join(SERVER_IDS)}")

    mcp = FastMCP(
        name=f"norviq-demo-{server_id}",
        instructions=_INSTRUCTIONS[server_id],
        host=host,
        port=port,
        streamable_http_path="/mcp",
        # STATELESS. Under MCP 2026-07-28 protocol-level sessions are gone (SEP-2567) and any request
        # may land on any replica; a stateful server would hand out an Mcp-Session-Id that the next
        # request -- possibly to a different pod, certainly through a proxy that does not track
        # sessions -- would fail to present. Stateless is also what makes `replicas: 2` a
        # non-decision rather than a debugging session.
        stateless_http=True,
        # Leave json_response at its default (False) so responses come back as SSE. The firewall
        # streams and mediates SSE frames; handing it a bare JSON body on a request whose Accept
        # asked for a stream is a shape it does not expect.
        json_response=False,
    )
    _register_diagnostics(mcp, server_id)
    _REGISTRARS[server_id](mcp)
    return mcp


async def verify_catalog(mcp: FastMCP, server_id: str) -> list[str]:
    """Assert the advertised catalog matches CONTRACT_TOOLS; return the tool names, sorted.

    Startup is the last moment a wrong tool name is cheap. After that it is a policy that never
    matches and a test that passes for the wrong reason.
    """
    advertised = {tool.name for tool in await mcp.list_tools()}
    expected = CONTRACT_TOOLS[server_id]
    if advertised != expected:
        missing = sorted(expected - advertised)
        extra = sorted(advertised - expected)
        raise RuntimeError(
            f"demo_mcp: {server_id} catalog does not match the contract "
            f"(missing={missing}, unexpected={extra})"
        )
    return sorted(advertised)
