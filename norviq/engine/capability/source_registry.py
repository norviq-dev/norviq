# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Source capability registry.

The asset graph tells you an agent *calls a tool* that *reaches a data source*. That is (as San put
it) "already known info." The value this module adds is a model of what a SOURCE can *do* — the verb
surface a datastore / egress / object-store exposes — so the console can distinguish a read hop from a
destructive one, flag verbs that are reachable-but-unguarded (undefended), and flag grants that are
never exercised (dormant, a least-privilege gap).

Design (per the phased plan, decision c):
  * Model the SOURCE CLASS (datastore / egress / object-store) from day one so egress
    (send_email/webhook/upload — first-class agent-exfil risk, already in comprehensive.rego) and
    object-stores slot in without a refactor.
  * Ship Elasticsearch + PostgreSQL (wave 1). SMTP/webhook (egress) and S3 (object-store) are modelled
    here too but marked wave 2 — their verb specs exist so the classifier already works on them.
  * This module is PURE (no I/O, no graph coupling): callers pass in the sets of granted / observed /
    policy-referenced verbs and get back per-verb findings. That keeps it unit-testable and lets both
    the asset-graph and attack-graph routes reuse one classifier.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from norviq.engine.graph.models import RiskLevel


class SourceClass(str, Enum):
    """The kind of resource a data node represents. Drives which verbs are even meaningful."""

    DATASTORE = "datastore"        # queryable store: postgres, elasticsearch, mongo…
    EGRESS = "egress"              # outbound channel: smtp, webhook, http-post (data LEAVES)
    OBJECT_STORE = "object_store"  # blob store: s3, gcs, filesystem
    UNKNOWN = "unknown"


class Verb(str, Enum):
    """The abstract operation a tool performs against a source. The registry maps concrete tool-name
    fragments to these; severity/technique attach at the verb level, not the tool level."""

    READ = "read"      # search / get / list / query — reconnaissance & exfiltration-by-query
    WRITE = "write"    # insert / update / index / put — integrity risk (e.g. RAG-KB poisoning)
    DELETE = "delete"  # delete / drop / truncate / purge — availability / destruction
    SEND = "send"      # egress only: the act of transmitting data outward
    UNKNOWN = "unknown"


class CapabilityStatus(str, Enum):
    """Per-verb posture, worst-first. 'Open' verbs (undefended/observed-undefended) are the finding."""

    UNDEFENDED = "undefended"                # observed in traffic AND no policy rule guards it — live gap
    DORMANT_GRANT = "dormant_grant"          # granted/reachable but never exercised — least-privilege gap
    DEFENDED = "defended"                    # observed AND a policy rule references it — covered
    LATENT = "latent"                        # the source exposes it, but nothing grants/observes it — informational
    NOT_EXPOSED = "not_exposed"              # this source class doesn't have this verb


@dataclass(frozen=True)
class _VerbSpec:
    verb: Verb
    risk: RiskLevel
    # A REAL MITRE ATLAS technique id, or None when no single technique fits (we never fabricate ids —
    # see the AML.T0000 removal). None renders as a tactic-level label in the UI, not a fake code.
    technique: str | None
    label: str
    # Tool-name fragments (lowercased substring match) that indicate this verb.
    tool_fragments: tuple[str, ...]
    # Verb-specific remediation fragment ("… for {class}"), composed by callers into a full suggestion.
    fix: str


@dataclass(frozen=True)
class _SourceSpec:
    source_type: str
    source_class: SourceClass
    display: str
    wave: int  # 1 = shipped/validated, 2 = modelled-but-not-yet-primary
    verbs: tuple[_VerbSpec, ...]


@dataclass
class VerbFinding:
    """One verb of one source, classified against the join of grants/observations/policy."""

    verb: Verb
    risk: RiskLevel
    technique: str | None
    label: str
    status: CapabilityStatus
    granted: bool
    observed: bool
    defended: bool
    recommendation: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "verb": self.verb.value,
            "risk": self.risk.value,
            "technique": self.technique,
            "label": self.label,
            "status": self.status.value,
            "granted": self.granted,
            "observed": self.observed,
            "defended": self.defended,
            "recommendation": self.recommendation,
        }


# ── the registry ──────────────────────────────────────────────────────────────────────────────────
# ATLAS ids used below are the real ones already present elsewhere in the codebase's mapping; where no
# single technique fits (plain reads), technique is None (tactic-level label, no fabricated id).

_READ = _VerbSpec(
    Verb.READ, RiskLevel.LOW, None, "read / search",
    ("search", "read", "get", "list", "query", "fetch", "select", "scan"),
    "keep read-only and namespace-scoped",
)


def _es_specs() -> tuple[_VerbSpec, ...]:
    return (
        _READ,
        _VerbSpec(
            Verb.WRITE, RiskLevel.HIGH, "AML.T0018", "write / index (knowledge poisoning)",
            ("index", "write", "update", "put", "upsert", "bulk"),
            "block writes to the retrieval index — a poisoned KB steers every downstream agent",
        ),
        _VerbSpec(
            Verb.DELETE, RiskLevel.CRITICAL, "AML.T0048", "delete / drop (availability)",
            ("delete", "drop", "purge", "truncate", "clear"),
            "block destructive verbs — deletion of the index is an availability attack",
        ),
    )


def _pg_specs() -> tuple[_VerbSpec, ...]:
    return (
        _READ,
        _VerbSpec(
            Verb.WRITE, RiskLevel.HIGH, None, "write / update",
            ("insert", "write", "update", "put", "upsert", "modify"),
            "constrain writes to the intended tables/columns",
        ),
        _VerbSpec(
            Verb.DELETE, RiskLevel.CRITICAL, "AML.T0048", "delete / drop / truncate",
            ("delete", "drop", "truncate", "purge"),
            "block destructive SQL (DROP/DELETE/TRUNCATE) for this class",
        ),
    )


def _egress_specs() -> tuple[_VerbSpec, ...]:
    # Egress has one meaningful verb — the act of sending data outward is itself the risk (LLM02 /
    # exfiltration). comprehensive.rego already treats send_email/post_webhook/upload_file as external.
    return (
        _VerbSpec(
            Verb.SEND, RiskLevel.HIGH, "AML.T0040", "send / egress (data exfiltration)",
            ("send", "post", "upload", "publish", "webhook", "http", "email", "sms", "export"),
            "restrict egress to allowed destinations and scan payloads for secrets/PII",
        ),
    )


def _object_store_specs() -> tuple[_VerbSpec, ...]:
    return (
        _READ,
        _VerbSpec(
            Verb.WRITE, RiskLevel.HIGH, None, "put / upload",
            ("put", "write", "upload", "post"),
            "constrain object writes to intended buckets/prefixes",
        ),
        _VerbSpec(
            Verb.DELETE, RiskLevel.CRITICAL, "AML.T0048", "delete object",
            ("delete", "remove", "purge"),
            "block object deletion for this class",
        ),
    )


_REGISTRY: dict[str, _SourceSpec] = {
    "elasticsearch": _SourceSpec("elasticsearch", SourceClass.DATASTORE, "Elasticsearch", 1, _es_specs()),
    "postgresql": _SourceSpec("postgresql", SourceClass.DATASTORE, "PostgreSQL", 1, _pg_specs()),
    # Wave-2, modelled so the classifier already works when these sources appear:
    "smtp": _SourceSpec("smtp", SourceClass.EGRESS, "SMTP / email", 2, _egress_specs()),
    "webhook": _SourceSpec("webhook", SourceClass.EGRESS, "Webhook", 2, _egress_specs()),
    "s3": _SourceSpec("s3", SourceClass.OBJECT_STORE, "S3", 2, _object_store_specs()),
    "filesystem": _SourceSpec("filesystem", SourceClass.OBJECT_STORE, "Filesystem", 2, _object_store_specs()),
}

# Aliases: real deployments name the same source-type differently.
_ALIASES = {
    "postgres": "postgresql", "psql": "postgresql", "pg": "postgresql",
    "es": "elasticsearch", "opensearch": "elasticsearch",
    "mail": "smtp", "email": "smtp", "ses": "smtp",
    "http": "webhook", "https": "webhook",
    "gcs": "s3", "blob": "s3", "minio": "s3",
    "fs": "filesystem", "file": "filesystem",
}

_RISK_ORDER = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}


def source_type_of(data_uri: str) -> str:
    """The registry key for a data URI like 'postgresql/users' or 'es://kb' → 'postgresql'/'elasticsearch'.
    Returns '' when the source type is unknown (caller renders it as an unclassified source)."""
    if not data_uri:
        return ""
    head = data_uri.split("://", 1)[0] if "://" in data_uri else data_uri.split("/", 1)[0]
    head = head.strip().lower()
    if head in _REGISTRY:
        return head
    return _ALIASES.get(head, "")


def verb_of_tool(tool_name: str, source_type: str) -> Verb:
    """Best-effort verb for a concrete tool name against a source type (substring match on the source's
    verb fragments; DELETE/WRITE win over READ when a name matches several, so 'delete_record' isn't READ)."""
    spec = _REGISTRY.get(source_type)
    if not spec:
        return Verb.UNKNOWN
    name = (tool_name or "").lower()
    # Match most-destructive first so a name containing both (rare) resolves to the higher risk.
    for spec_verb in sorted(spec.verbs, key=lambda v: _RISK_ORDER[v.risk], reverse=True):
        if any(frag in name for frag in spec_verb.tool_fragments):
            return spec_verb.verb
    return Verb.UNKNOWN


# ── DYNAMIC, SOURCE-AGNOSTIC tool classification ──────────────────────────────────────────────────
# In a real k8s deployment a tool may hit ANY backend — AWS, Azure, GCS, an open-source service, a
# control-plane — with arbitrary names: aws_s3_DeleteObject, azure_blob_read, gcs.bucket.list,
# open_breaker, invoke_lambda, rotate_key, transfer_funds. classify_tool must identify what ANY of them
# DOES so the operator's allow/deny decision is informed. It does NOT rely on a fixed source registry.
#
# Approach (name-structural, not substring-soup):
#   1. TOKENIZE the name: split on non-alphanumerics AND camelCase (DeleteObject → [delete, object]),
#      lowercase. This avoids the classic substring bug (‘put’ inside ‘input’, ‘get’ inside ‘widget’) —
#      we match whole VERB TOKENS, not fragments.
#   2. Look each token up in a VERB LEXICON (token → (verb, risk)). Easily extended: add a token, done.
#   3. An ACTUATION noun (breaker/valve/relay/…) present with any control verb ⇒ critical control-plane.
#   4. When the name is inconclusive, optionally inspect tool_params (a SQL statement, an http/destination
#      field) to recover the operation.
#   5. Pick the WORST (most destructive) match. Unknown ⇒ (UNKNOWN, None) so the UI flags "review", never
#      silently "safe".

# token → (Verb, RiskLevel). Destruction/exec/actuation are CRITICAL (a security operator must never see a
# destructive capability mislabelled benign). Egress + writes are HIGH. Reads are LOW.
_VERB_LEXICON: dict[str, tuple[Verb, RiskLevel]] = {}


def _reg(verb: Verb, risk: RiskLevel, *tokens: str) -> None:
    for t in tokens:
        _VERB_LEXICON[t] = (verb, risk)


# destruction
_reg(Verb.DELETE, RiskLevel.CRITICAL,
     "delete", "del", "drop", "truncate", "purge", "destroy", "remove", "rm", "erase", "wipe", "revoke",
     "terminate", "kill", "deprovision", "teardown", "uninstall", "expire", "invalidate", "flush")
# code-exec / control-plane actuation (also critical — an exec or actuation is not a mere write)
_reg(Verb.DELETE, RiskLevel.CRITICAL,
     "exec", "execute", "eval", "invoke", "run", "spawn", "shell", "sh", "bash", "cmd", "system",
     "actuate", "trip", "detonate", "fire", "launch", "reboot", "restart", "shutdown", "halt", "detach")
# writes / mutations
_reg(Verb.WRITE, RiskLevel.HIGH,
     "write", "update", "insert", "put", "upsert", "patch", "modify", "set", "create", "add", "append",
     "grant", "approve", "issue", "provision", "mint", "sign", "rotate", "enable", "disable", "configure",
     "register", "attach", "bind", "apply", "commit", "save", "store", "tag", "label")
# egress / exfiltration (data leaving)
_reg(Verb.SEND, RiskLevel.HIGH,
     "send", "post", "upload", "publish", "webhook", "email", "mail", "sms", "notify", "export",
     "transfer", "push", "sync", "forward", "relay", "emit", "dispatch", "share", "leak", "exfiltrate")
# reads (low)
_reg(Verb.READ, RiskLevel.LOW,
     "read", "get", "list", "search", "query", "fetch", "scan", "describe", "select", "lookup", "view",
     "show", "find", "count", "head", "exists", "meter", "monitor", "watch", "tail", "retrieve", "load",
     "peek", "download", "poll", "check", "inspect", "status")

# actuation NOUNS — with a control verb (open/close/set/toggle) these mean a physical/control-plane command.
_ACTUATION_NOUNS = {"breaker", "valve", "relay", "switch", "actuator", "damper", "motor", "pump", "throttle",
                    "circuit", "grid", "turbine", "reactor", "solenoid", "contactor"}
_CONTROL_VERBS = {"open", "close", "toggle", "set", "adjust", "override", "reset", "engage", "disengage"}

_VERB_ORDER = {Verb.DELETE: 3, Verb.SEND: 2, Verb.WRITE: 1, Verb.READ: 0, Verb.UNKNOWN: -1}

_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _tokenize_tool(name: str) -> list[str]:
    """Split a tool name into lowercased word tokens on non-alphanumerics AND camelCase boundaries, so
    'aws_s3_DeleteObject', 's3:DeleteObject', 'delete-record' all yield ['delete', …]. Whole-token matching
    avoids substring false positives ('put' in 'input', 'get' in 'budget')."""
    spaced = _CAMEL_RE.sub(" ", name or "")
    return [t.lower() for t in re.split(r"[^A-Za-z0-9]+", spaced) if t and not t.isdigit()]


def _classify_params(tool_params: object) -> tuple[Verb, RiskLevel] | None:
    """Recover the operation from tool_params when the NAME is inconclusive: a SQL statement's leading verb,
    or an egress signal (a destination/recipient/url field). Best-effort, string-walking, None if nothing."""
    if not isinstance(tool_params, dict):
        return None
    egress_keys = {"destination", "recipient", "to", "url", "endpoint", "webhook", "email", "callback"}
    for key, val in tool_params.items():
        if isinstance(key, str) and key.lower() in egress_keys:
            return Verb.SEND, RiskLevel.HIGH
        if isinstance(val, str):
            low = val.strip().lower()
            if low.startswith(("drop ", "delete ", "truncate ")) or "; drop" in low or "; delete" in low:
                return Verb.DELETE, RiskLevel.CRITICAL
            if low.startswith(("insert ", "update ", "merge ", "alter ", "create ")):
                return Verb.WRITE, RiskLevel.HIGH
            if low.startswith("select "):
                return Verb.READ, RiskLevel.LOW
            if low.startswith(("http://", "https://")):
                return Verb.SEND, RiskLevel.HIGH
    return None


def classify_tool(tool_name: str, tool_params: object = None) -> tuple[Verb, RiskLevel | None]:
    """Dynamic (verb, risk) for ANY tool — cloud, opensource, control-plane — with no source-registry
    dependency. Tokenizes the name, matches whole verb tokens against the lexicon, recognises control-plane
    actuations, and falls back to inspecting tool_params. Returns the WORST operation found, or
    (UNKNOWN, None) when genuinely inconclusive (the UI then flags it 'unclassified — review', never 'safe').
    Extend by adding a token to the lexicon — the classifier stays dynamic and data-driven."""
    tokens = _tokenize_tool(tool_name)
    tset = set(tokens)
    matches: list[tuple[Verb, RiskLevel]] = []

    # control-plane actuation: an actuation noun + a control verb ⇒ critical (open_breaker, set_valve).
    if tset & _ACTUATION_NOUNS and tset & _CONTROL_VERBS:
        matches.append((Verb.DELETE, RiskLevel.CRITICAL))

    for t in tokens:
        hit = _VERB_LEXICON.get(t)
        if hit:
            matches.append(hit)

    if not matches:
        params_hit = _classify_params(tool_params)
        if params_hit:
            matches.append(params_hit)

    if not matches:
        return Verb.UNKNOWN, None
    # worst first: higher RiskLevel, then more-destructive verb.
    verb, risk = max(matches, key=lambda m: (_RISK_ORDER[m[1]], _VERB_ORDER[m[0]]))
    return verb, risk


_DEFAULT_VERB_RISK = {
    Verb.READ: RiskLevel.LOW,
    Verb.WRITE: RiskLevel.HIGH,
    Verb.SEND: RiskLevel.HIGH,
    Verb.DELETE: RiskLevel.CRITICAL,
}


def default_risk_of_verb(verb: Verb) -> RiskLevel | None:
    """The canonical risk a verb carries absent source-specific context (read=low, write/send=high,
    delete=critical) — used when an admin PROMOTES an observed tool to a verb: the promotion names the
    verb, the risk follows from this map so it can never be under-declared. None for UNKNOWN."""
    return _DEFAULT_VERB_RISK.get(verb)


def verb_risk(source_type: str, verb: Verb) -> RiskLevel | None:
    """The RiskLevel a source assigns to a verb (e.g. DELETE on postgres = CRITICAL, READ = LOW), or None
    when the source type or verb isn't in the registry. Lets callers colour a hop by its real operation risk."""
    spec = _REGISTRY.get(source_type)
    if not spec:
        return None
    for vs in spec.verbs:
        if vs.verb == verb:
            return vs.risk
    return None


def classify_source(
    source_type: str,
    *,
    granted_verbs: set[Verb] | None = None,
    observed_verbs: set[Verb] | None = None,
    defended_verbs: set[Verb] | None = None,
) -> list[VerbFinding]:
    """Classify every verb a source EXPOSES against the join of what is granted / observed / policy-defended.

    granted  = a tool reaching this source that maps to the verb is registered/allowed
    observed = real traffic exercised the verb
    defended = a policy rule references the verb/tool

    Returns findings worst-first (UNDEFENDED → DORMANT_GRANT → DEFENDED → LATENT), each with a
    verb-specific recommendation. Callers derive per-source/per-path severity via worst_open_verb()."""
    spec = _REGISTRY.get(source_type)
    if not spec:
        return []
    granted = granted_verbs or set()
    observed = observed_verbs or set()
    defended = defended_verbs or set()

    findings: list[VerbFinding] = []
    for vs in spec.verbs:
        is_granted = vs.verb in granted or vs.verb in observed
        is_observed = vs.verb in observed
        is_defended = vs.verb in defended
        if is_observed and not is_defended:
            status = CapabilityStatus.UNDEFENDED
        elif is_granted and not is_observed:
            status = CapabilityStatus.DORMANT_GRANT
        elif is_observed and is_defended:
            status = CapabilityStatus.DEFENDED
        else:
            status = CapabilityStatus.LATENT

        rec = ""
        if status == CapabilityStatus.UNDEFENDED:
            rec = f"{vs.fix} — {spec.display}"
        elif status == CapabilityStatus.DORMANT_GRANT:
            rec = f"grant is unused — revoke {vs.verb.value} on {spec.display} (least privilege)"
        findings.append(
            VerbFinding(
                verb=vs.verb, risk=vs.risk, technique=vs.technique, label=vs.label,
                status=status, granted=is_granted, observed=is_observed, defended=is_defended,
                recommendation=rec,
            )
        )

    findings.sort(key=lambda f: (_STATUS_ORDER[f.status], -_RISK_ORDER[f.risk]))
    return findings


_STATUS_ORDER = {
    CapabilityStatus.UNDEFENDED: 0,
    CapabilityStatus.DORMANT_GRANT: 1,
    CapabilityStatus.DEFENDED: 2,
    CapabilityStatus.LATENT: 3,
    CapabilityStatus.NOT_EXPOSED: 4,
}


def worst_open_verb(findings: list[VerbFinding]) -> VerbFinding | None:
    """The highest-risk verb that is 'open' (undefended or a dormant grant) — the severity a path/source
    should carry. Returns None when everything is defended or latent (nothing actionable)."""
    open_findings = [f for f in findings if f.status in (CapabilityStatus.UNDEFENDED, CapabilityStatus.DORMANT_GRANT)]
    if not open_findings:
        return None
    return max(open_findings, key=lambda f: (_RISK_ORDER[f.risk], f.status == CapabilityStatus.UNDEFENDED))


def source_meta(source_type: str) -> dict[str, object] | None:
    """Display metadata for a source type (class + label + wave), or None if unknown."""
    spec = _REGISTRY.get(source_type)
    if not spec:
        return None
    return {"source_type": spec.source_type, "source_class": spec.source_class.value, "display": spec.display, "wave": spec.wave}


# ── capability → policy bridge helpers ──────────────────────────────────────────────────────────────
# The OPA evaluate input carries no data-source field (only tool_name + agent), so a "block WRITE on
# Elasticsearch" defense cannot match on the source at enforce time. It is instead resolved to a concrete
# tool-name set AT GENERATION TIME (the tools that reach the source with the target verb) — these helpers
# provide the verb metadata; the router joins it against the live asset graph.

# Verbs that MUTATE or EXFILTRATE (the ones a "make read-only" defense should block); read is the
# legitimate use and is never blocked.
_MUTATING = (Verb.WRITE, Verb.DELETE, Verb.SEND)


def verb_display(verb: Verb) -> str:
    return {Verb.READ: "read", Verb.WRITE: "write", Verb.DELETE: "delete", Verb.SEND: "send"}.get(verb, "?")


def mutating_verbs_of(source_type: str) -> list[Verb]:
    """The mutating/egress verbs this source EXPOSES — the set a 'make read-only' defense blocks."""
    spec = _REGISTRY.get(source_type)
    if not spec:
        return []
    exposed = {vs.verb for vs in spec.verbs}
    return [v for v in _MUTATING if v in exposed]


def verb_fragments(source_type: str, verbs: list[Verb]) -> list[str]:
    """The tool-name fragments that identify ``verbs`` for ``source_type`` (e.g. delete → drop/purge/
    truncate). A capability defense blocks any tool whose name matches one of these at a word boundary —
    so the policy is a FORWARD GUARD (it catches a delete tool that appears LATER, and a renamed
    delete_records/drop_table), not just the exact tool names observed at generation time. READ is never
    included. Deduped, sorted longest-first so a broader fragment can't shadow a longer one."""
    spec = _REGISTRY.get(source_type)
    if not spec:
        return []
    want = {v for v in verbs if v in _MUTATING}
    frags: set[str] = set()
    for vs in spec.verbs:
        if vs.verb in want:
            frags.update(f.strip().lower() for f in vs.tool_fragments if f.strip())
    return sorted(frags, key=lambda f: (-len(f), f))


def defense_meta(source_type: str, verbs: list[Verb]) -> dict[str, object] | None:
    """Metadata for a capability defense that blocks ``verbs`` on ``source_type``: a stable rule_id token,
    a human reason, and the worst risk among the verbs (for the draft's severity). Returns None for an
    unknown source or an empty/READ-only verb set (reads are never blocked — nothing to defend)."""
    spec = _REGISTRY.get(source_type)
    if not spec:
        return None
    by_verb = {vs.verb: vs for vs in spec.verbs}
    targets = [v for v in verbs if v in by_verb and v in _MUTATING]
    if not targets:
        return None
    targets.sort(key=lambda v: _RISK_ORDER[by_verb[v].risk], reverse=True)
    worst = by_verb[targets[0]]
    verb_names = "/".join(verb_display(v) for v in targets)
    reason = f"Blocked: {verb_names} on {spec.display} for this class (capability policy — least privilege)"
    return {
        "verbs": [v.value for v in targets],
        "rule_id": f"capability:{source_type}:{'+'.join(verb_display(v) for v in targets)}",
        "reason": reason,
        "risk": worst.risk.value,
        "technique": worst.technique,
        "source_display": spec.display,
        # blocking ALL of the source's mutating verbs == making the class read-only (set compare — targets
        # is risk-sorted, mutating_verbs_of is in fixed order).
        "read_only": set(targets) == set(mutating_verbs_of(source_type)),
    }
