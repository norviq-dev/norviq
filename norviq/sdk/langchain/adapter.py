# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""LangChain adapter for Norviq tool interception.

This module also hosts the DECLARED-SCHEMA INGESTION shared by all five framework adapters — see the
banner below for what it does and why it lives here rather than in ``norviq.sdk.core``.

GOVERNED SURFACE (F-026): per-TOOL wrapping. `protect(tools, ...)` replaces `_run`/`_arun` on each
tool you hand it. A tool NOT passed to `protect()` runs with NO policy enforcement — Norviq's PEP is
cooperative, so it governs the calls routed through the wrapper and cannot see the ones that are not.
`allow_unwrapped=False` (the default) makes an unrecognised item a loud startup error rather than a
silently ungoverned tool.
"""

import inspect
import re
import threading
import unicodedata
from dataclasses import dataclass
from types import UnionType
from typing import Any, Union, get_args, get_origin, get_type_hints

import structlog

from norviq.sdk.core.interceptor import ToolInterceptor
from norviq.sdk.core.interceptor import depth_scope
from norviq.sdk.core.wrapping import _output_dlp, _run_sync, _tool_params, callable_signature

log = structlog.get_logger()


# ══ DECLARED ARGUMENT SCHEMAS ═══════════════════════════════════════════════════════════════════
#
# WHY THIS EXISTS. Every framework here already holds a statement of what arguments a tool takes —
# LangChain and CrewAI build ``args_schema`` from the tool's own implementation, AutoGen publishes an
# OpenAI-style ``schema``, Semantic Kernel carries ``KernelParameterMetadata``. All of them ship that
# statement to the MODEL on every call. The adapters read ``.name`` off the tool object and threw the
# rest away, so Norviq knew that a tool called ``issue_refund`` existed and NOTHING about the
# ``amount`` argument it takes. Two operators authored a rule that could only name the tool, and were
# surprised in production by an argument nobody had ever shown them.
#
# It is ingestion, never re-declaration: the user has explicitly refused to write, a second time in
# Norviq, the schema they already wrote in their agent framework. Nothing here adds an authoring step.
#
# THREE PROPERTIES THIS MUST HAVE, in order of importance:
#
#   1. IT MUST NEVER BREAK WRAPPING. These are third-party objects: the attribute may be absent, may
#      be a class or an instance, may be a property that raises, may be enormous, may be circular. A
#      framework whose tools stop working because Norviq could not parse a schema is a far worse
#      product than one that records no schema. Every failure mode lands on "unknown".
#   2. IT MUST NEVER CHANGE WHAT THE ENGINE EVALUATES. The evaluate payload is built from the ACTUAL
#      call by ``wrapping._tool_params`` and is untouched by anything here. This is observational.
#   3. "UNKNOWN" MUST NOT BE SPELLED LIKE "EMPTY". A tool whose schema we could not read and a tool
#      that genuinely declares no arguments are opposite instructions to an operator — one says keep
#      looking, the other says stop — so ``param_keys is None`` (unknown) and ``param_keys == ()``
#      (declares nothing) are different states, and an incomplete key-set says so via
#      ``param_keys_truncated``. A partial set reported as complete is the fail-open class this
#      codebase keeps hitting.
#
# KEYS ONLY. Declared defaults are VALUES (``api_key: str = "sk-live-…"`` is a real pattern) and no
# value — masked, defaulted or otherwise — is read out of a schema here. Only names are.
#
# THE NAMES ARE UNTRUSTED TEXT. A schema can come from an MCP server or any third-party tool package,
# so a key name is attacker-influenced and is rendered in the console. It is stored VERBATIM (the
# engine's ``param_paths`` does the same, because an operator scopes against the path they saw) and
# every consumer must treat it as untrusted.
#
#   ...which means a NAME CAN LIE ABOUT WHICH ARGUMENT IT IS, and saying nothing about that is the
#   same fail-open the engine already closed on the traffic side. `evaluator._walk_paths` publishes
#   `param_paths_ambiguous` for exactly two reasons, and a DECLARED schema can produce both:
#     * a key that MINTS a path another route also reaches — `{"wire": {"destination": ...},
#       "wire.destination": ...}` declares TWO arguments and flattens to ONE name. Deduplicating them
#       into a single key and reporting the set as complete is a partial answer wearing the costume
#       of a whole one.
#     * two keys that RENDER identically — `amount` beside Cyrillic-а `аmount`, `To` beside `to`,
#       NFC beside NFD. The console prints one thing twice; a rule pinned on what the operator saw
#       binds whichever twin the reader resolves.
#   Both are named in ``param_keys_ambiguous`` and neither key is rewritten, mirroring the engine.
#
# WHY IT LIVES IN THE LANGCHAIN ADAPTER. It belongs in ``norviq/sdk/core/`` next to ``wrapping.py``,
# and it is here only because this change is scoped to the five adapter modules; the other four
# import it from here. Nothing in this module imports LangChain at module scope (the framework loads
# lazily in ``_get_base_tool``), so importing it costs a CrewAI/AutoGen/SK user nothing — a property
# that must hold if this stays put. Moving it to ``norviq.sdk.core.tool_schema`` is a pure
# relocation.

# Bounds. A schema is third-party data walked at wrap time, so every dimension is capped. These
# MIRROR the evaluator's derived-path bounds (`_MAX_PATHS` 256, `_MAX_PATH_KEY_LEN` 256,
# `_MAX_PATH_DEPTH` 12) so a declared path and an observed path are bounded the same way and one
# cannot silently out-range the other. They are restated rather than imported because importing
# `norviq.engine.evaluator` would drag OPA and Redis into every SDK-only install.
MAX_DECLARED_PARAM_KEYS = 256
MAX_DECLARED_KEY_LEN = 256
MAX_DECLARED_DEPTH = 12
# Total fields visited across the whole walk, so a wide-and-deep (or circular) schema cannot make
# wrap time unbounded even while staying under the per-dimension caps.
_MAX_SCHEMA_NODES = 512
# Typing-annotation nodes scanned when deciding whether a container hides a nested model.
_MAX_ANNOTATION_NODES = 64
# Registered tools kept in the process-local registry.
_MAX_REGISTERED_TOOLS = 1024

# Why no schema could be read. Each is a distinct diagnosis and none of them means "no arguments".
REASON_ABSENT = "no_declared_schema"          # the framework object carries no schema at all
REASON_UNREADABLE = "schema_unreadable"       # reading it raised — a property, a lazy proxy, a bug
REASON_UNRECOGNIZED = "schema_shape_unknown"  # it exists and is not a shape we can read names from
REASON_REGISTRY_FULL = "registry_full"        # the process-local registry is saturated; not walked

_UNSET = object()
_UNION_ORIGINS = (Union, UnionType)
# Structural characters of the path grammar. A key containing one of these can assert a position
# that a genuinely nested route also reaches — see `_mints_a_path` in the evaluator, whose rule this
# copies exactly (including the part that makes an OTel-style `http.method` ORDINARY, not forged).
_PATH_HEAD_RE = re.compile(r"[.\[\]]")


@dataclass(frozen=True)
class DeclaredToolSchema:
    """What the FRAMEWORK says a tool's arguments are called. Names only; never values.

    ``param_keys`` is the sorted, de-duplicated set of flattened argument paths, in the engine's own
    path syntax (dots for object keys), or ``None`` when no schema could be read. ``None`` and ``()``
    are deliberately different: the first is "we do not know", the second is "the framework says
    there are none".

    ``param_keys_ambiguous`` is the subset of those paths that does NOT name exactly one declared
    argument — either two declared routes flattened onto it, or another declared path renders
    identically to it. It is a subset of ``param_keys`` and never a replacement for it: the keys are
    published verbatim, as the engine publishes ambiguous ``param_paths`` verbatim, because an
    operator scopes against the name they were shown. A consumer that renders a name from this tuple
    without saying it is ambiguous is showing one label for two arguments.

    THERE IS DELIBERATELY NO ``param_keys_pinnable`` HERE, and no consumer may invent a permissive
    default for its absence. The audit-row side publishes that field as a POSITIVE set derived from
    an ACTUAL value by the engine's own flattener, precisely so that a reader which does not find it
    pins nothing. A declared schema has no values, so the same fact cannot be derived here, and
    guessing it from a declared TYPE would put two different derivations under one name. This
    matters concretely: ``input.derived.param_paths`` carries STRING leaves only, so a rule pinned
    on a numeric ``amount`` is false on EVERY call, and under `default decision = "block"` an allow
    arm that never matches refuses every call to the tool. SHOW every declared name; assert none of
    them from this record alone.
    """

    tool: str
    framework: str
    source: str
    param_keys: tuple[str, ...] | None
    param_keys_truncated: bool
    unavailable_reason: str
    param_keys_ambiguous: tuple[str, ...] = ()

    @property
    def schema_available(self) -> bool:
        """True only when a schema was actually read — an empty declaration still counts as read."""
        return self.param_keys is not None

    def as_dict(self) -> dict[str, Any]:
        """A JSON-shaped copy. ``param_keys`` stays ``None`` when unknown; it never becomes ``[]``."""
        return {
            "tool": self.tool,
            "framework": self.framework,
            "source": self.source,
            "schema_available": self.schema_available,
            "param_keys": list(self.param_keys) if self.param_keys is not None else None,
            "param_keys_truncated": self.param_keys_truncated,
            "param_keys_ambiguous": list(self.param_keys_ambiguous),
            "unavailable_reason": self.unavailable_reason,
        }


class _Walk:
    """Mutable state for one bounded schema walk."""

    __slots__ = ("keys", "truncated", "nodes", "ambiguous")

    def __init__(self) -> None:
        """Start with an empty, untruncated, unspent walk."""
        self.keys: set[str] = set()
        # Paths that do not name exactly one declared argument. Kept beside `keys`, never instead of
        # them: dropping a colliding name would make the set quietly shorter than the declaration.
        self.ambiguous: set[str] = set()
        self.truncated = False
        self.nodes = 0


def _model_fields(obj: Any) -> dict[str, Any] | None:
    """The pydantic field map of a model CLASS or INSTANCE (v2 then v1), else None.

    Duck-typed rather than `isinstance(obj, BaseModel)`: a tool may declare a `pydantic.v1` model
    inside a pydantic-v2 process, and an isinstance check against the wrong BaseModel would report
    a perfectly readable schema as unknown. An EMPTY field map is returned as `{}`, not None — a
    model that declares no fields is a fact, not a failure.
    """
    holder = obj if isinstance(obj, type) else type(obj)
    for attr in ("model_fields", "__fields__"):
        try:
            fields = getattr(holder, attr, None)
        except Exception:  # noqa: BLE001 - third-party descriptors may raise; that is "unknown"
            return None
        if isinstance(fields, dict):
            return fields
    return None


def _field_annotation(field: Any) -> Any:
    """The declared type of one pydantic field (v2 ``annotation``, v1 ``outer_type_``), or None."""
    for attr in ("annotation", "outer_type_", "type_"):
        try:
            value = getattr(field, attr, None)
        except Exception:  # noqa: BLE001 - an unreadable annotation just means "do not expand"
            return None
        if value is not None:
            return value
    return None


def _json_schema_fields(schema: dict, *, allow_envelope: bool = True) -> list[tuple[str, Any]] | None:
    """``[(declared name, its sub-schema)]`` for a JSON-Schema-shaped declaration, else None.

    Three shapes reach here and they must not be confused with each other, because guessing wrong
    invents argument names that no tool has: a JSON Schema object (``{"type": "object",
    "properties": {...}}``), an OpenAI-style tool envelope (``{"name": ..., "parameters": {...}}``,
    which is what AutoGen publishes), and a bare property map (``{"to": {...}, "body": {...}}``,
    which is what LangChain's ``.args`` returns).

    The discriminators are deliberately value-shaped, not key-presence: a bare property map CAN have
    an argument called ``properties``, ``parameters``, ``name`` or ``type`` — but then its value is a
    sub-schema DICT, not the string ``"object"`` and not a name. Reading such a tool's arguments as
    though the map were an envelope would report its nested keys as top-level argument names, which
    is the "wrong name" failure this codebase already paid for once on the binding path.
    """
    properties = schema.get("properties")
    if isinstance(properties, dict) and (
        schema.get("type") == "object" or "$schema" in schema or isinstance(schema.get("required"), list)
    ):
        return [(str(name), value) for name, value in properties.items()]
    parameters = schema.get("parameters")
    if allow_envelope and isinstance(parameters, dict) and isinstance(schema.get("name"), str):
        # One unwrap only: `allow_envelope=False` below makes a self-referential dict impossible to
        # recurse on.
        return _json_schema_fields(parameters, allow_envelope=False)
    if not schema:
        return []  # an empty declaration IS a declaration: this tool takes nothing
    if all(isinstance(value, dict) for value in schema.values()):
        return [(str(name), value) for name, value in schema.items()]
    return None


def _schema_fields(schema: Any) -> list[tuple[str, Any]] | None:
    """``[(declared name, its child declaration)]`` for anything recognised, else None (= unknown)."""
    fields = _model_fields(schema)
    if fields is not None:
        return [(str(name), _field_annotation(field)) for name, field in fields.items()]
    if isinstance(schema, dict):
        return _json_schema_fields(schema)
    if isinstance(schema, (list, tuple)):
        # Semantic Kernel: a list of KernelParameterMetadata, each a `name` plus a per-parameter
        # JSON Schema on `schema_data`. An item without a name means this is not a parameter list at
        # all, and reporting the ones we could read would understate the tool.
        out: list[tuple[str, Any]] = []
        for item in schema:
            try:
                name = getattr(item, "name", None)
                child = getattr(item, "schema_data", None)
            except Exception:  # noqa: BLE001
                return None
            if not isinstance(name, str):
                return None
            out.append((name, child))
        return out
    return None


def _hides_a_model(annotation: Any) -> bool:
    """Whether a container annotation could hold argument names we are not expanding.

    ``list[LineItem]`` declares names (``sku``, ``qty``) that a traffic path spells ``items[0].sku``.
    A declared schema has no index to put there, so inventing ``items[].sku`` would mint a path form
    nothing else in this system produces. We name ``items`` and report the key-set as incomplete —
    "there is more here" rather than a path the operator can pin and never match.
    """
    stack = [annotation]
    seen = 0
    while stack:
        item = stack.pop()
        seen += 1
        if seen > _MAX_ANNOTATION_NODES:
            return True  # out of budget: "there may be more" is the only honest answer
        if isinstance(item, type) and _model_fields(item) is not None:
            return True
        try:
            stack.extend(get_args(item))
        except Exception:  # noqa: BLE001 - an un-introspectable annotation may hide anything
            return True
    return False


def _child_declaration(child: Any) -> tuple[Any | None, bool]:
    """``(nested declaration to expand or None, whether unexpanded names may hide behind it)``."""
    if child is None:
        return None, False
    if isinstance(child, dict):
        if isinstance(child.get("properties"), dict):
            return child, False
        if "$ref" in child:
            # Deliberately not resolved: `$defs` chasing is unbounded and cyclic in practice.
            return None, True
        for key in ("items", "additionalProperties", "anyOf", "oneOf", "allOf"):
            value = child.get(key)
            if isinstance(value, dict) and ("properties" in value or "$ref" in value):
                return None, True
            if isinstance(value, (list, tuple)) and any(
                isinstance(item, dict) and ("properties" in item or "$ref" in item) for item in value
            ):
                return None, True
        return None, False
    if isinstance(child, type) and _model_fields(child) is not None:
        return child, False
    if get_origin(child) in _UNION_ORIGINS:
        args = [arg for arg in get_args(child) if arg is not type(None)]
        if len(args) == 1 and isinstance(args[0], type) and _model_fields(args[0]) is not None:
            return args[0], False  # Optional[Model] is still one nested object
    return None, _hides_a_model(child)


def _mints_a_path(name: str, siblings: set[str]) -> bool:
    """True when this declared KEY can assert a path a genuinely nested sibling also reaches.

    The evaluator's rule, copied so a declared path and an observed path are judged the same way.
    Path syntax in a name is NOT by itself a forgery: `{"attributes": {"http.method": ...}}` and
    `{"filter[status]": ...}` are ordinary arguments, and calling them ambiguous would make the exact
    name the operator sees permanently unscopable. What is dangerous is a SECOND ROUTE — and any
    honest route to a path under this object begins with a key OF this object, so the second route
    exists exactly when the name's first structural segment is also a sibling name.
    """
    head = _PATH_HEAD_RE.split(name, 1)[0]
    if head == name:
        return False  # no path syntax in the name: it can only name itself
    return head in siblings


def _fold_path(path: str) -> str:
    """The form in which two declared paths are INDISTINGUISHABLE to whoever reads them.

    ASCII folds by case. Anything else is NFKC-normalised, casefolded, and stripped of combining
    marks and zero-width / format / control characters — so `café` composed and decomposed, `Amount`
    and `amount`, and `amo<ZWSP>unt` and `amount` all land on one form.

    This is a SUBSET of `norviq.engine.confusables.skeleton`, which additionally maps cross-script
    look-alikes to their ASCII prototype. That module is stdlib-only, but importing it executes
    `norviq/engine/__init__.py`, which pulls in the evaluator, Redis and SQLAlchemy — a cost an
    SDK-only install must not pay. Cross-script impersonation is therefore caught by
    `_mixes_latin_with_another_script` instead, which needs no table.
    """
    if path.isascii():
        return path.casefold()
    folded = unicodedata.normalize("NFKC", path).casefold()
    return "".join(ch for ch in folded if unicodedata.category(ch) not in ("Mn", "Me", "Cf", "Cc"))


def _mixes_latin_with_another_script(path: str) -> bool:
    """True when a name mixes Latin letters with letters of some other script.

    That is the whole shape of the homoglyph attack on an argument name: `аmount` is Cyrillic `а`
    wearing Latin `mount`, and a console prints it exactly like `amount`. Deliberately narrower than
    "is not ASCII" — a legitimately Cyrillic or Japanese argument name is SINGLE-script and is not
    flagged, which is the same restraint the engine's confusables module documents. Table-free: the
    script is read off the character's Unicode name.
    """
    if path.isascii():
        return False
    scripts: set[str] = set()
    for ch in path:
        if not ch.isalpha():
            continue
        try:
            scripts.add(unicodedata.name(ch).split(" ", 1)[0])
        except ValueError:
            scripts.add("UNNAMED")  # a letter with no assigned name is not a name we can vouch for
        if len(scripts) > 1 and "LATIN" in scripts:
            return True
    return False


def _collect(schema: Any, prefix: str, depth: int, state: _Walk) -> bool:
    """Add every declared path under ``schema`` to ``state``; True if it emitted at least one."""
    if depth > MAX_DECLARED_DEPTH:
        state.truncated = True
        return False
    fields = _schema_fields(schema)
    if fields is None:
        state.truncated = True  # something unreadable sits here; the set is not complete
        return False
    siblings = {name for name, _ in fields if name}
    emitted = False
    for name, child in fields:
        state.nodes += 1
        if state.nodes > _MAX_SCHEMA_NODES:
            state.truncated = True
            break
        if not name:
            state.truncated = True
            continue
        path = f"{prefix}.{name}" if prefix else name
        if len(path) > MAX_DECLARED_KEY_LEN:
            # A CLIPPED name is a name the tool does not have, and two long siblings clip onto ONE
            # path. Dropping it and saying so beats publishing a name nothing can ever match.
            state.truncated = True
            continue
        if len(state.keys) >= MAX_DECLARED_PARAM_KEYS:
            state.truncated = True
            break
        if _mints_a_path(name, siblings):
            state.ambiguous.add(path)
        nested, may_hide = _child_declaration(child)
        if nested is not None and _collect(nested, path, depth + 1, state):
            emitted = True
            continue  # leaf paths only, exactly like the engine's param_paths
        if may_hide:
            state.truncated = True
        if path in state.keys:
            # Two declared arguments, one flattened name. The set is now SHORTER than the
            # declaration, so it is both ambiguous and incomplete — reporting it as a complete list
            # of what this tool takes is the partial-set-as-whole failure this module exists to
            # avoid, and it is what an operator would have authored a rule against.
            state.ambiguous.add(path)
            state.truncated = True
        state.keys.add(path)
        emitted = True
    return emitted


def _declared_param_keys(schema: Any) -> tuple[tuple[str, ...] | None, bool, tuple[str, ...]]:
    """``(sorted paths or None, truncated, ambiguous paths)`` — None when no names are readable.

    The render-twin pass is hard-bounded at ``MAX_DECLARED_PARAM_KEYS × MAX_DECLARED_KEY_LEN``
    character inspections and short-circuits on ``str.isascii()``, so ordinary tools pay nothing:
    measured 0.20 ms for a 400-field ASCII schema and 5.0 ms for the worst case this module admits
    (256 paths of 200 non-ASCII characters). It runs once per tool, never per call.
    """
    if _schema_fields(schema) is None:
        return None, False, ()
    state = _Walk()
    _collect(schema, "", 0, state)
    # Paths that RENDER as one thing are one thing to everyone downstream — the console, a rule
    # label, an operator reading a diff. Raw string comparison cannot see it: NFC and NFD "café" are
    # different dict keys. Both twins are named; neither is rewritten.
    folded: dict[str, str] = {}
    for path in state.keys:
        if _mixes_latin_with_another_script(path):
            state.ambiguous.add(path)
        twin = folded.setdefault(_fold_path(path), path)
        if twin != path:
            state.ambiguous.add(path)
            state.ambiguous.add(twin)
    return tuple(sorted(state.keys)), state.truncated, tuple(sorted(state.ambiguous))


_DECLARED_LOCK = threading.Lock()
_DECLARED: dict[tuple[str, str], DeclaredToolSchema] = {}
# One warning per process, not one per attempt. Semantic Kernel ingests from INSIDE the filter, so a
# refusal that also logged would put a log write on the evaluate path of every single tool call.
_REGISTRY_FULL_LOGGED = False


def declared_tool_schemas() -> dict[tuple[str, str], DeclaredToolSchema]:
    """Snapshot of every declared schema ingested in this process, keyed by ``(framework, tool)``.

    Keyed by both because the same tool name can be registered by two frameworks with different
    argument shapes, and silently collapsing them would report one tool's arguments for the other.
    """
    with _DECLARED_LOCK:
        return dict(_DECLARED)


def declared_tool_schema(framework: str, tool: str) -> DeclaredToolSchema | None:
    """One record, or None if this tool's schema was never ingested.

    Exists so a caller on a hot path (Semantic Kernel ingests on first sight, inside the filter) can
    ask about ONE tool without copying the whole registry per invocation.
    """
    with _DECLARED_LOCK:
        return _DECLARED.get((framework, tool))


def forget_declared_tool_schemas() -> None:
    """Drop every ingested record — for hosts that re-register a whole tool set, and for tests."""
    global _REGISTRY_FULL_LOGGED
    with _DECLARED_LOCK:
        _DECLARED.clear()
        _REGISTRY_FULL_LOGGED = False


def _registry_has_room_for(framework: str, tool: str) -> bool:
    """Whether a record for this tool could be stored, warning ONCE per process if not.

    Read before the walk, not after it. A saturated registry cannot keep a new record, so a caller
    that ingests on first sight — Semantic Kernel, inside the filter — would find nothing cached,
    re-walk the schema and re-log on EVERY tool call, forever. Unbounded repeated work in front of
    `intercept_or_raise` is an availability defect on an engine that fails closed at a 2s timeout.
    """
    global _REGISTRY_FULL_LOGGED
    with _DECLARED_LOCK:
        if (framework, tool) in _DECLARED or len(_DECLARED) < _MAX_REGISTERED_TOOLS:
            return True
        already_warned, _REGISTRY_FULL_LOGGED = _REGISTRY_FULL_LOGGED, True
    if not already_warned:
        log.warning(
            "nrvq.sdk.schema.registry_full",
            tool=tool,
            framework=framework,
            limit=_MAX_REGISTERED_TOOLS,
            code="NRVQ-SDK-1082",
        )
    return False


def _remember(record: DeclaredToolSchema) -> None:
    """Store a record, refusing to grow the registry without bound.

    A record with no tool name names no tool, so it is never stored: an entry under ``""`` would
    accumulate whatever the last nameless object happened to declare and report it as a tool.
    """
    if not record.tool:
        return
    with _DECLARED_LOCK:
        key = (record.framework, record.tool)
        if key not in _DECLARED and len(_DECLARED) >= _MAX_REGISTERED_TOOLS:
            return  # already reported by _registry_has_room_for; never log from the hot path
        _DECLARED[key] = record


def _carry_on_tool(tool: Any, record: DeclaredToolSchema) -> None:
    """Best-effort: hang the record on the tool so it travels with the object it describes.

    Third-party objects may forbid attribute assignment; the registry is the durable carrier, so a
    refusal here is not an error.
    """
    try:
        tool._norviq_declared_schema = record
    except Exception:  # noqa: BLE001 - carrying the record must never break wrapping
        pass


def ingest_declared_schema(
    tool: Any,
    *,
    tool_name: str,
    framework: str,
    attrs: tuple[str, ...] = (),
    schema: Any = _UNSET,
    source: str = "",
) -> DeclaredToolSchema:
    """Read the framework's own argument declaration for ``tool``, record it, and return it.

    ``attrs`` are attribute paths to try in order (dotted paths allowed, e.g.
    ``metadata.parameters``); the first that is not ``None`` wins and names the ``source``. Pass
    ``schema=`` instead when the caller already holds the declaration.

    NEVER RAISES. Every failure — a missing attribute, a property that explodes, a shape we cannot
    read — produces a record whose ``schema_available`` is False and whose ``unavailable_reason``
    says which. Wrapping continues either way.
    """
    name = str(tool_name or "")
    try:
        if name and not _registry_has_room_for(framework, name):
            # Saturated: nothing can be stored, so walking the schema would be work whose result is
            # discarded. Answer in O(1) and say WHY — "unknown", never "no arguments".
            return DeclaredToolSchema(
                tool=name,
                framework=framework,
                source="",
                param_keys=None,
                param_keys_truncated=False,
                unavailable_reason=REASON_REGISTRY_FULL,
            )
        found: Any = schema
        found_source = source
        if found is _UNSET:
            found = None
            unreadable = False
            for attr in attrs:
                try:
                    value: Any = tool
                    for part in attr.split("."):
                        value = getattr(value, part, None)
                        if value is None:
                            break
                except Exception:  # noqa: BLE001 - a property that raises is "unreadable"
                    # ...but only for THIS source. `attrs` are independent statements of the same
                    # fact — LangChain answers `.args` when `args_schema` is a property that
                    # explodes, SK answers `.parameters` when `.metadata` does — and abandoning the
                    # rest would report "unknown" for a tool whose argument names are right there.
                    unreadable = True
                    continue
                if value is not None:
                    found, found_source = value, attr
                    break
            if found is None and unreadable:
                return _finish(tool, name, framework, "", None, False, REASON_UNREADABLE)
        if found is None:
            # Nothing to read. Note `[]` and `{}` are NOT None: an empty declaration is a statement
            # that the tool takes no arguments, and it must not land here.
            return _finish(tool, name, framework, "", None, False, REASON_ABSENT)
        keys, truncated, ambiguous = _declared_param_keys(found)
        reason = "" if keys is not None else REASON_UNRECOGNIZED
        return _finish(tool, name, framework, found_source, keys, truncated, reason, ambiguous)
    except Exception as exc:  # noqa: BLE001 - ingestion must never break tool wrapping
        try:
            log.warning(
                "nrvq.sdk.schema.ingest_failed",
                tool=name,
                framework=framework,
                error=str(exc),
                code="NRVQ-SDK-1083",
            )
            return _finish(tool, name, framework, source, None, False, REASON_UNREADABLE)
        except Exception:  # noqa: BLE001 - the last resort still has to return, not raise
            return DeclaredToolSchema(
                tool=name,
                framework=framework,
                source="",
                param_keys=None,
                param_keys_truncated=False,
                unavailable_reason=REASON_UNREADABLE,
            )


def _finish(
    tool: Any,
    tool_name: str,
    framework: str,
    source: str,
    keys: tuple[str, ...] | None,
    truncated: bool,
    reason: str,
    ambiguous: tuple[str, ...] = (),
) -> DeclaredToolSchema:
    """Build, log, register and attach one record.

    The key NAMES are deliberately not logged. Log lines are size-bounded in every collector, so a
    line carrying up to 256 names would be clipped by the pipeline and would then read as a COMPLETE
    argument list that is silently missing entries — the exact confusion `param_keys_truncated`
    exists to prevent. The honest count and the truncation flag go to the log; the names go to the
    registry, which cannot be clipped behind our back.
    """
    record = DeclaredToolSchema(
        tool=tool_name,
        framework=framework,
        source=source if keys is not None else "",
        param_keys=keys,
        param_keys_truncated=truncated,
        unavailable_reason=reason,
        param_keys_ambiguous=ambiguous if keys is not None else (),
    )
    _remember(record)
    _carry_on_tool(tool, record)
    if record.schema_available:
        log.info(
            "nrvq.sdk.schema.ingested",
            tool=tool_name,
            framework=framework,
            source=record.source,
            param_key_count=len(keys or ()),
            param_keys_truncated=truncated,
            param_keys_ambiguous_count=len(record.param_keys_ambiguous),
            code="NRVQ-SDK-1080",
        )
    else:
        log.info(
            "nrvq.sdk.schema.unavailable",
            tool=tool_name,
            framework=framework,
            reason=reason,
            code="NRVQ-SDK-1081",
        )
    return record


# LangChain publishes `args_schema` (a pydantic model, or a JSON Schema dict on langchain-core 1.x).
# A tool that declares none still answers `.args` — LangChain derives it from the tool's own `_run`
# and sends THAT to the model — so it is the second-best statement of the same fact, not a guess.
LANGCHAIN_SCHEMA_ATTRS = ("args_schema", "args")


def _mirror_signature(wrapper: Any, original: Any) -> None:
    """Make ``wrapper`` present ``original``'s call signature *and type hints* to introspection.

    LangChain/LangGraph decide which extra kwargs (``config``, ``run_manager``) to inject into
    ``_run``/``_arun`` by inspecting the target. Our wrapper is ``(*args, **kwargs)``, so without this
    LangChain injects nothing and the *original* ``StructuredTool._run`` — which requires a keyword-only
    ``config`` on langchain-core 1.x — then fails with "missing argument 'config'".

    It uses *two* detection mechanisms, and both must see the original's shape:
      * ``run_manager`` via ``inspect.signature(func).parameters`` — honored by ``__signature__``;
      * ``config`` via ``typing.get_type_hints(func)`` (it looks for the ``RunnableConfig``-typed
        parameter) — honored by ``__annotations__``, NOT ``__signature__``.
    So we mirror both. The hints are resolved in the *original's* module globals here (turning string
    annotations like ``"RunnableConfig"`` into the real type) so the wrapper carries concrete types the
    caller's ``get_type_hints`` can read without needing those names imported in this module.

    We deliberately do NOT set ``__wrapped__``: a ``__wrapped__`` attribute lets ``inspect.unwrap``
    reach the original callable directly, which would let a framework call the tool body *bypassing*
    Norviq's interception — a silent enforcement bypass. Mirroring keeps the wrapper on the call path.
    """
    try:
        wrapper.__signature__ = inspect.signature(original)
    except (ValueError, TypeError):  # some builtins/callables have no introspectable signature
        pass
    try:
        wrapper.__annotations__ = dict(get_type_hints(original))
    except Exception:  # noqa: BLE001 — unresolvable/absent hints must not break wrapping
        pass


def _get_base_tool() -> type[Any]:
    """Load LangChain BaseTool class lazily."""
    try:
        from langchain_core.tools import BaseTool
    except ImportError:
        from langchain.tools import BaseTool
    return BaseTool


def protect(
    tools: list[Any], interceptor: ToolInterceptor, session_id: str = "", *, allow_unwrapped: bool = False
) -> list[Any]:
    """Wrap LangChain tools so policy runs before execution.

    In sync-in-async usage, prefer `_arun` because async Redis clients are event-loop bound.

    Fail-closed by default: a framework upgrade that moves/renames `BaseTool` (or a caller that
    hands in something that was never a `BaseTool`) must be a loud startup error, not a silently
    unprotected tool — an item Norviq doesn't recognize as a `BaseTool` cannot be wrapped, so
    letting it through unwrapped means it runs with NO policy enforcement at all. Pass
    `allow_unwrapped=True` to downgrade this to a logged warning and accept the item as-is.
    """
    base_tool = _get_base_tool()
    protected: list[Any] = []
    for tool in tools:
        if not isinstance(tool, base_tool):
            if not allow_unwrapped:
                raise TypeError(
                    f"norviq.sdk.langchain.adapter.protect: {type(tool).__name__!r} is not a "
                    f"{base_tool.__name__} instance and cannot be wrapped — fail-closed protection: "
                    "this tool would run WITHOUT policy enforcement. Pass allow_unwrapped=True to "
                    "permit it deliberately."
                )
            log.warning(
                "nrvq.langchain.unwrapped",
                tool_type=type(tool).__name__,
                code="NRVQ-SDK-1044",
            )
            protected.append(tool)
            continue
        # BEFORE `_run` is replaced, on purpose. LangChain derives `.args` from the tool's `_run`
        # when no `args_schema` was declared, so reading it after the swap would describe OUR
        # wrapper instead of the tool.
        ingest_declared_schema(
            tool, tool_name=str(tool.name), framework="langchain", attrs=LANGCHAIN_SCHEMA_ATTRS
        )
        original_run = tool._run
        original_arun = getattr(tool, "_arun", None)

        # The names this tool binds positionally, read from its OWN `_run`. Without them a
        # positionally-invoked tool reached the engine as `{"args": [...]}` — every per-argument
        # control addresses a parameter by NAME, so none of them could fire.
        sync_sig = callable_signature(original_run)

        def sync_wrapper(*args: Any, _name: str = tool.name, _orig: Any = original_run,
                         _sig: object = sync_sig, **kwargs: Any) -> Any:
            _run_sync(
                interceptor.intercept_or_raise(
                    tool_name=_name,
                    tool_params=_tool_params(args, kwargs, _sig),
                    session_id=session_id,
                    framework="langchain",
                )
            )
            log.info("nrvq.langchain.allowed", tool=_name, code="NRVQ-SDK-1030")
            with depth_scope():
                return _output_dlp(_name, _orig(*args, **kwargs))

        _mirror_signature(sync_wrapper, original_run)
        tool._run = sync_wrapper  # type: ignore[method-assign]
        if original_arun is not None:

            async_sig = callable_signature(original_arun)

            async def async_wrapper(
                *args: Any, _name: str = tool.name, _orig: Any = original_arun,
                _sig: object = async_sig, **kwargs: Any
            ) -> Any:
                await interceptor.intercept_or_raise(
                    tool_name=_name,
                    tool_params=_tool_params(args, kwargs, _sig),
                    session_id=session_id,
                    framework="langchain",
                )
                log.info("nrvq.langchain.allowed", tool=_name, code="NRVQ-SDK-1030")
                with depth_scope():
                    return _output_dlp(_name, await _orig(*args, **kwargs))

            _mirror_signature(async_wrapper, original_arun)
            tool._arun = async_wrapper  # type: ignore[method-assign]
        protected.append(tool)
        log.debug("nrvq.langchain.protected", tool=tool.name, code="NRVQ-SDK-1031")
    log.info("nrvq.langchain.protect", count=len(protected), code="NRVQ-SDK-1032")
    return protected
