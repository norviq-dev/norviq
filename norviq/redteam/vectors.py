# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The MCP + tool attack-vector catalog, and what the red-team suite can actually measure.

`docs/design/MCP-TOOL-ATTACK-SURFACE.md` enumerates the surface in prose. This module promotes those
ids into code so the suite can score against them AND — the part that matters — so it can state what
it did NOT measure. A scorecard reading 100% across three vectors while thirty are unexercised is the
"the console says covered, and it is not" failure this product exists to prevent, so the denominator
ships with the numerator.

WHY THESE IDS. Three identifier sets existed and only one is a vector taxonomy:
  * the kebab ids below — one id per attack vector, whole surface, each already carrying an
    OWASP/ATLAS mapping in the doc. Nothing in code had claimed them, so promoting them costs no
    migration. This is the spine.
  * `mcp_a_*` (norviq/mcp/scanner.py) — DETECTOR ids. Several vectors share one, several have none.
    They ride along as `expected_evidence`; keying on them would conflate "what fired" with "what was
    attacked".
  * `D1-D12` / `G1-G6` (docs/design/THREAT-COVERAGE.md) — document-local gap numbers that collide
    semantically across documents and include engine/builder defects with no MCP surface at all.

REACHABILITY is the honest half. The suite evaluates in-process against the policy engine
(`norviq/api/routers/redteam.py` -> `evaluator.evaluate`), so it can only adjudicate what a POLICY
decides. The rule applied below:

    Does the outcome turn on a policy decision the engine renders, given facts that exist today?
    If the outcome is produced by proxy code BEFORE or INSTEAD OF `_evaluate`, it is PROXY —
    even when the suite could physically send the payload.

That rule is deliberately conservative and it is why the exercised count is small. Reclassifying a
PROXY vector as EVALUATE to make the number look better would restore exactly the overclaim the
coverage block exists to prevent. The lever for a better number is writing more attacks against the
EVALUATE set, or moving a vector into policy reach — never re-labelling one.

PROXY vectors are NOT unprotected. Most are enforced, several provably (see the live results in
docs/design/MCP-RED-BLUE-LOOP.md, where Gate A stripped tool-description poisoning and invisible
tag-character steganography, and the content-hash pin refused a rug-pull). They are simply not
measured HERE, by THIS suite. `scripts/kind-e2e/mcp_red_team.py` measures them against a live proxy
with an ungoverned control, which is the only way to prove a proxy behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Reachability(str, Enum):
    """Whether the in-process red-team suite can adjudicate this vector."""

    EVALUATE = "evaluate"          # a policy decision the suite can ask for and score
    PROXY = "proxy"                # decided by proxy code before/instead of the policy engine
    OUT_OF_SCOPE = "out_of_scope"  # not a per-call enforcement question at all


class VectorSurface(str, Enum):
    MCP_PROTOCOL = "mcp-protocol"
    MCP_IDENTITY_TRANSPORT = "mcp-identity-transport"
    TOOL_RUNTIME = "tool-runtime"


@dataclass(frozen=True, slots=True)
class McpVector:
    """One attack vector. `reason` is REQUIRED for anything the suite cannot score — an unmeasured
    vector with no stated reason is indistinguishable from an oversight, which is the thing this
    catalog exists to make impossible."""

    id: str
    surface: VectorSurface
    title: str
    reachability: Reachability
    reason: str = ""
    expected_evidence: tuple[str, ...] = ()


_P = VectorSurface.MCP_PROTOCOL
_I = VectorSurface.MCP_IDENTITY_TRANSPORT
_R = VectorSurface.TOOL_RUNTIME
_EVAL = Reachability.EVALUATE
_PROXY = Reachability.PROXY
_OOS = Reachability.OUT_OF_SCOPE

# Recurring reasons, named once so the catalog reads as a classification rather than 29 restatements.
_NEVER_EVALUATED = (
    "never reaches the policy engine — the proxy's dispatch forwards or refuses this method before "
    "any /evaluate call exists, so there is no decision for the suite to score"
)
_DISCOVERY_PLANE = (
    "decided once at discovery (tools/list, prompts/get, resources/list) against the pin registry and "
    "the definition scanner, not per call — the suite evaluates calls, so it would measure the wrong "
    "layer"
)
_PROXY_STRUCTURAL = (
    "enforced structurally in the proxy BEFORE /evaluate, so scoring the engine would report red for "
    "a control that is working"
)
_TRANSPORT = (
    "a transport/session-layer property of the connection, not a fact in any call's policy input"
)

VECTORS: tuple[McpVector, ...] = (
    # ---- mcp-protocol ---------------------------------------------------------------------------
    McpVector("init-capability-negotiation-unmediated", _P,
              "initialize / capability negotiation never inspected or constrained", _PROXY, _NEVER_EVALUATED),
    McpVector("elicitation-create-ungoverned", _P,
              "server asks the human mid-call; demand and answer unadjudicated", _PROXY, _NEVER_EVALUATED),
    McpVector("sampling-response-egress-unguarded", _P,
              "the model's completion flows client->server with no DLP, scan or decision", _PROXY, _NEVER_EVALUATED),
    McpVector("schema-conformance-unenforced", _P,
              "pinned inputSchema checked against actual arguments", _PROXY,
              # The doc still lists this ABSENT. It shipped: _schema_violations (firewall.py:593) is
              # enforced at :750 under mcp_enforce_schema, which defaults True (config.py:220).
              "shipped and enforced in the proxy before /evaluate — a violation is refused there, and "
              "the engine only ever sees calls that already conformed"),
    McpVector("proxy-bypass-remote-mcp-server", _P,
              "an in-process MCP client has no PEP in path at all", _OOS,
              "the suite calls the evaluator directly and so structurally cannot observe its own "
              "absence; detecting ungoverned MCP is a fleet/coverage question, not a call decision"),
    McpVector("prompts-list-unscanned-unpinned", _P,
              "prompts/list invisible; no prompt primitive ever pinned", _PROXY, _DISCOVERY_PLANE),
    McpVector("resources-list-and-templates-invisible", _P,
              "resources/list and server-authored uriTemplate never scanned or pinned", _PROXY, _DISCOVERY_PLANE),
    McpVector("roots-scope-disclosure", _P,
              "client hands the server its filesystem scope; scope never a constraint", _PROXY, _NEVER_EVALUATED),
    McpVector("cross-server-name-shadowing", _P,
              "homoglyph shadowing detected within one server, never across servers", _PROXY,
              "the skeleton map is per-proxy-instance and the webhook runs one proxy per server, so "
              "the collision is invisible at the point a call is decided"),
    McpVector("server-minted-handles-as-bearer-capability", _P,
              "server handles ride in tool_params as unbound bearer capabilities", _PROXY,
              "binding a handle to its issuing caller needs state the policy input does not carry; a "
              "handle is just a string to the engine today"),
    McpVector("schema-remote-ref-indirection", _P,
              "$ref in inputSchema — the pin hashes a pointer, the contract changes with no drift", _PROXY,
              _DISCOVERY_PLANE),
    McpVector("logging-notification-channel", _P,
              "notifications/message — attacker text into operator logs and model context", _PROXY, _NEVER_EVALUATED),
    McpVector("progress-notification-channel", _P,
              "notifications/progress free text and unbounded out-of-band flood", _PROXY, _NEVER_EVALUATED),
    McpVector("cacheable-list-results-unhandled", _P,
              "cacheScope: public / ttlMs parsed and ignored", _PROXY, _DISCOVERY_PLANE),
    McpVector("tool-added-midsession-never-pinned", _P,
              "a tool appearing mid-session is callable with pin_status unknown", _PROXY, _DISCOVERY_PLANE),
    McpVector("tofu-first-sight-window", _P,
              "a server hostile from its first tools/list is auto-approved", _PROXY, _DISCOVERY_PLANE),
    McpVector("server-content-indirect-injection", _P,
              "tool results and resource bodies fenced and masked, never blocked", _PROXY,
              "acts on the RESULT after the call was decided; the response plane has no /evaluate hook "
              "the suite can drive"),
    McpVector("subscriptions-listen-narrow-guard", _P,
              "stream never authorised; content guard keyed on attacker-controlled metadata", _PROXY,
              _NEVER_EVALUATED),
    McpVector("server-discover-flagged-not-blocked", _P,
              "the mandatory discovery response is annotated, never refused or pinned", _PROXY, _DISCOVERY_PLANE),
    McpVector("resources-read-uri-gate", _P,
              "the non-tool read channel adjudicated as a call", _EVAL,
              "the proxy really does call _evaluate(surface='resources/read') and honours a block — "
              "what is missing is a RULE, not a mechanism, which is exactly a policy question"),
    McpVector("tools-list-rug-pull", _P,
              "a tool definition changes after approval", _PROXY, _DISCOVERY_PLANE,
              ("mcp_a_hidden_marker", "mcp_a_exfil_directive")),
    McpVector("tool-definition-poisoning-scan", _P,
              "instruction text in a description or schema, withheld at discovery", _PROXY, _DISCOVERY_PLANE,
              ("mcp_a_instruction_override", "mcp_a_concealment", "mcp_a_credential_read",
               "mcp_a_hidden_marker", "mcp_a_authority_claim")),
    McpVector("prompts-get-template-poisoning", _P,
              "a poisoned prompt template withheld", _PROXY, _DISCOVERY_PLANE,
              ("mcp_a_instruction_override",)),
    McpVector("x-mcp-header-parameter-smuggling", _P,
              "model-controlled tool params reaching the outbound header layer", _PROXY, _PROXY_STRUCTURAL),
    McpVector("jsonrpc-batch-smuggling", _P,
              "a tools/call riding inside a batch array", _PROXY, _PROXY_STRUCTURAL),

    # ---- mcp-identity-transport -----------------------------------------------------------------
    McpVector("child-process-inherits-norviq-credentials", _I,
              "the untrusted MCP server inherits the PEP's own credentials", _OOS,
              "a process-environment property established at spawn; no call carries it, so no policy "
              "decision can express it"),
    McpVector("mcp-server-identity-unattested", _I,
              "server_id is a self-asserted string", _EVAL,
              "every input.mcp field is attacker-chosen on the wire — a crafted /evaluate carrying a "
              "forged mcp document is precisely the shape this suite sends"),
    McpVector("token-passthrough-confused-deputy", _I,
              "the agent's user credential relayed verbatim to the MCP server", _PROXY,
              "the credential is at the upstream during initialize, before any JSON-RPC decision exists"),
    McpVector("oauth-flows-for-mcp-unmediated", _I,
              "code theft, redirect abuse, consent phishing, over-broad scopes", _OOS,
              "there is no OAuth on the agent->server leg to attack; brokering it is a product to build, "
              "not a control to measure"),
    McpVector("mcp-server-id-homoglyph-squat", _I,
              "server-id homoglyph or typosquat; confusables cover tool names only", _PROXY,
              "distinct codepoints are distinct pin rows by construction, so the squat is resolved at "
              "registration, not at call time"),
    McpVector("static-secrets-in-server-config-uninventoried", _I,
              "static API keys on MCP server containers; no credential dimension anywhere", _OOS,
              "a PodSpec inventory question — there is no server-level row to hang a credential fact on, "
              "and nothing reaches a call's policy input"),
    McpVector("tls-downgrade-mitm-upstream", _I,
              "plain-http upstream accepted, no pinning", _PROXY, _TRANSPORT),
    McpVector("upstream-session-hijack-and-relay", _I,
              "client-chosen mcp-session-id relayed to the upstream unbound", _PROXY, _TRANSPORT),
    McpVector("session-keying-attested-not-client-header", _I,
              "Gate-A state confusion via a client-chosen session id", _PROXY, _TRANSPORT),

    # ---- tool-runtime and engine ------------------------------------------------------------------
    McpVector("sdk-tool-schema-never-captured", _R,
              "for every non-MCP framework tool, Norviq holds no declared shape at all", _OOS,
              "an ingestion gap in the SDK adapters — there is no call to send that makes a missing "
              "schema into a decision"),
    McpVector("eval-cache-key-omits-mcp-context", _R,
              "a cached decision served across different MCP contexts", _EVAL,
              # Closed by the cache-key fix; kept EVALUATE because it IS an engine-adjudicable property,
              # and it will show in `unexercised_reachable` until the corpus can express a paired attack.
              "closed by adding the MCP document to the cache key; regression-tested directly at "
              "tests/engine/test_cache_key_scope.py, which flips each of the twelve reported facts — a "
              "stronger guard than a suite attack, which cannot express two evaluations resolving to "
              "one verdict"),
    McpVector("sdk-unwrapped-tool-ungoverned", _R,
              "a tool never passed to protect() runs with no policy", _OOS,
              "detecting the ABSENCE of a call is not something a suite that sends calls can measure"),
    McpVector("sdk-output-plane-default-off", _R,
              "non-MCP tool results carry PAN/SSN unmasked by default", _PROXY,
              "acts on the result after the decision; a response-plane control with no /evaluate hook"),

    # ---- minted here ------------------------------------------------------------------------------
    # No id existed for this anywhere — not in the surface doc, not in THREAT-COVERAGE's D#/G# gaps.
    # It is the highest-severity finding of the live red/blue loop (MCP-RED-BLUE-LOOP.md, Finding 1).
    McpVector("base-allowlist-strips-baseline-floor", _R,
              "a per-class allowlist silently removes a baseline protection on every tool it grants", _EVAL,
              "base policies compose highest-priority-wins (evaluator.py `_resolve_precedence`) with the "
              "namespace baseline at priority 1, so this is decided entirely inside the engine on an "
              "ordinary call — plain tool_params, no MCP context, reachable in any namespace"),
)


def _validate() -> None:
    """Fail at import, not in production. A duplicate id would silently merge two vectors' scores; an
    unmeasured vector with no reason is indistinguishable from someone forgetting to classify it."""
    seen: set[str] = set()
    for v in VECTORS:
        if v.id in seen:
            raise ValueError(f"duplicate MCP vector id: {v.id}")
        seen.add(v.id)
        if v.reachability is not Reachability.EVALUATE and not v.reason.strip():
            raise ValueError(
                f"vector {v.id!r} is {v.reachability.value} and states no reason. Every vector this "
                "suite cannot score must say why, or the coverage block is an alibi rather than a fact."
            )


_validate()

VECTORS_BY_ID: dict[str, McpVector] = {v.id: v for v in VECTORS}
EVALUATE_REACHABLE: frozenset[str] = frozenset(
    v.id for v in VECTORS if v.reachability is Reachability.EVALUATE
)


def coverage_denominators() -> dict[str, int]:
    """The catalog half of `vector_coverage`. Counts only — stored on the run so the block survives
    detail-pruning (only the newest run per namespace keeps its result rows)."""
    return {
        "catalogued": len(VECTORS),
        "evaluate_reachable": sum(1 for v in VECTORS if v.reachability is Reachability.EVALUATE),
        "proxy_only": sum(1 for v in VECTORS if v.reachability is Reachability.PROXY),
        "out_of_scope": sum(1 for v in VECTORS if v.reachability is Reachability.OUT_OF_SCOPE),
    }


def vector_title(vector_id: str) -> str:
    v = VECTORS_BY_ID.get(vector_id)
    return v.title if v else vector_id
