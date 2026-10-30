# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Baseline controls: the shipped detectors, individually turned on, observed, or off.

A preset used to be all-or-nothing. Installing the chart put 22 block rules in front of every tool
call in every tenant namespace on day one, before the customer had written a policy or seen a single
decision — and one of those rules (`deny_shell_execution`, via the base64 fan-out) fired on roughly
1 in 8 ordinary alphanumeric identifiers until 0.2.1 narrowed it. There was no way to keep the
detector and stop it dropping traffic, short of turning the whole preset off.

This module makes each control independently settable:

    deny    -> the control blocks, exactly as the preset always did
    monitor -> the control EVALUATES, records the call as non-compliant, and lets it proceed
    off     -> the control is not evaluated at all

The mechanism is deliberately tiny, because the detection logic is the part that must not change. A
preset already registers each control as a one-line head on top of a named predicate:

    blocks["deny_shell_execution"] { shell_injection_detected }

so a control's effect is nothing more than WHICH SET the head registers into. `compile()` rewrites
only the marked CONTROLS region and leaves every predicate above it byte-identical. That is what
makes `tests/api/test_baseline_compiler.py::test_all_deny_is_behaviourally_identical_to_the_preset`
a meaningful safety net rather than a tautology.

Modelled on `norviq/api/packs.py`, which already splices marked regions out of rego fragments — same
markers, same `_between` shape, same "materialize into a reserved scope" flow.
"""

from __future__ import annotations

import functools
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import structlog

log = structlog.get_logger()

Effect = Literal["off", "monitor", "deny"]
EFFECTS: tuple[str, ...] = ("off", "monitor", "deny")

# The fallback for a control id the preset does not register. A registered control's default is how
# the preset authors it (`shipped_default`); this only keeps an unknown id from ever defaulting to deny.
DEFAULT_EFFECT: Effect = "monitor"

CONTROLS_BEGIN = "# >>> CONTROLS-BEGIN"
CONTROLS_END = "# >>> CONTROLS-END"
# Written into every compiled region: the controls the operator set to `off`, space-separated.
#
# `off` compiles to NO head, so without this line a compiled module cannot say whether a control is
# missing because the operator switched it off or because the compiler never knew it. The engine has
# to tell those apart: once a namespace's saved controls supersede the chart's baseline
# (`covers()`), a control missing for the second reason would be dropped without anyone choosing it.
# A comment, so it costs OPA nothing and `parse_heads` skips it.
CONTROLS_OFF = "# >>> CONTROLS-OFF:"

# `set["control_id"] { guard }` on ONE line. The preset carries a comment saying so, because a head
# wrapped across lines would not match here and the control would silently vanish from the compiled
# module — an "off" nobody chose. `_assert_region_fully_parsed` turns that into a loud error.
_HEAD_RE = re.compile(r'^(blocks|escalates|audits)\[\"([A-Za-z0-9_]+)\"\]\s*\{(.+)\}\s*$')

# Emitted for any of the three sets that ends up with no heads. A partial set with zero definitions is
# not an empty set in Rego — the symbol is undefined, and `block_fired { blocks[_] }` then fails to
# compile with `rego_unsafe_var_error: var blocks is unsafe`.
#
# This is not a theoretical edge case: it is the SHIPPED DEFAULT. With every control at `monitor`
# there are no `blocks[...]` heads at all, so without this line the default configuration produces a
# module that does not compile, every evaluation falls to `evaluator_error`, and an "allow by default"
# release would have blocked literally everything.
_NEVER_FIRES = '{set}[id] {{ false; id := "__never__" }}'

# The sentinel keys on a bare var rather than a string literal, so `_HEAD_RE` cannot read it back —
# and `parse_heads` is deliberately strict, so re-parsing a compiled module would explode on the
# compiler's own output. Recognised and skipped here rather than loosened into `_HEAD_RE`: keeping the
# head pattern tight is what makes an unreadable AUTHORED head a loud error instead of a silent "off".
#
# Recognised by EQUALITY with the exact lines `_render` writes, never by a prefix. It was a prefix
# (`blocks[id] { false;`), and Rego lets one head carry several bodies, so
# `blocks[id] { false; id := "__never__" } { input.tool_name == "send_newsletter"; id := "no_newsletter" }`
# is a real rule that looks like the placeholder for its first nineteen characters. In a chart's
# CONTROLS region that line was skipped as a placeholder, `_render` dropped it, `covers()` held, and
# after a save with nothing changed the chart's block on send_newsletter came back allow/default_allow.
# Exact, it is an unreadable head: `parse_heads` raises, and `covers()` keeps the chart as a floor.
_NEVER_FIRES_LINES = frozenset(_NEVER_FIRES.format(set=s) for s in ("blocks", "escalates", "audits"))


@dataclass(frozen=True, slots=True)
class ControlHead:
    """One registration line lifted out of a preset's CONTROLS region."""

    set_name: str
    control_id: str
    guard: str


#: Where a control acts, which is the axis the console groups on. Chosen over a threat taxonomy
#: because it mirrors the enforcement architecture an operator is actually reasoning about — Gate A at
#: discovery, Gate B at the call, the content guard on the way back — so the grouping teaches the model
#: rather than hiding it.
Plane = Literal["discovery", "call", "response"]

#: WHAT the control governs, which is the axis the console groups on at the top level.
#:
#: `plane` (above) says WHERE a control acts and stays the SUBGROUP: it is a real property and the
#: reason a discovery control cannot see call arguments. But it is the wrong first cut for a reader —
#: an operator arrives asking "what do my MCP integrations enforce", not "what happens at discovery",
#: and grouping by plane split the MCP controls across two sections with the tool controls wedged
#: between them.
#:
#: Server-side rather than derived from an `mcp_` id prefix in the console, for the reason the plane
#: field is: an id→group map in the UI drifts the moment a control is renamed, and nothing fails.
Surface = Literal["tool", "mcp"]


@dataclass(frozen=True, slots=True)
class Control:
    """A control as an operator sees it: what it catches, and what it costs to enforce."""

    id: str
    title: str
    description: str
    # Named so the console can warn before promotion. Empty when the control has no known
    # false-positive mode worth calling out.
    caveat: str = ""
    # No default effect here: a control's default is read from how the preset AUTHORS it
    # (`shipped_default`). This table used to carry one per control, and it disagreed with the preset.
    plane: Plane = "call"
    surface: Surface = "tool"


# Operator-facing copy. Keyed by control id; a control with no entry still works and falls back to the
# preset's own `reasons` text, so adding a control to a preset can never break this module.
#
# The `caveat` field exists because "promote this to deny" is the moment a customer needs to know what
# it will cost them, and that is exactly when nobody reads the docs.
_CONTROL_COPY: dict[str, Control] = {
    "llm01_prompt_injection": Control(
        "llm01_prompt_injection",
        "Prompt injection",
        "Catches instructions in tool parameters that try to override the agent's own instructions "
        "— 'ignore previous instructions', jailbreak phrasing, system-prompt exfiltration.",
        plane="call",
    ),
    "deny_sql_injection": Control(
        "deny_sql_injection",
        "SQL injection",
        "Catches destructive or injected SQL in any tool's parameters, not just execute_sql — a "
        "renamed tool carrying 'drop table users' is caught too.",
        plane="call",
    ),
    "deny_sql_multi_statement": Control(
        "deny_sql_multi_statement",
        "Multi-statement SQL",
        "Catches stacked statements and SQL metacharacters on execute_sql.",
        plane="call",
    ),
    "deny_shell_execution": Control(
        "deny_shell_execution",
        "Shell / command execution",
        "Catches shell metacharacters and command-execution patterns in tool parameters.",
        caveat="Guards the widest surface, so it is the one to observe first. Through 0.2.0 it "
        "matched single characters such as '|' in base64-DECODED parameter values, so ordinary "
        "identifiers — order ids, tracking codes, session tokens — decoded to random bytes and "
        "tripped it roughly 1 in 8 times. Fixed in 0.2.1: the decoded arm matches multi-byte "
        "indicators only, and bare metacharacters need an execution-shaped tool name.",
        plane="call",
    ),
    "llm06_excessive_agency": Control(
        "llm06_excessive_agency",
        "Destructive & elevated tools",
        "Blocks tools that delete or destroy, and escalates elevated ones.",
        plane="call",
    ),
    "llm02_data_leakage": Control(
        "llm02_data_leakage",
        "Secret egress",
        "Catches credentials and secrets sent to an external sink, on ANY tool name — including "
        "tool names it has never seen.",
        plane="call",
    ),
    "llm05_supply_chain": Control(
        "llm05_supply_chain",
        "Supply chain",
        "Blocks every call to a tool named install_package, load_plugin, download_script or eval.",
        caveat="Matches on the tool NAME, not the source: a pinned install from public PyPI is refused "
        "like any other. If your agents install packages, set this to monitor or allow that tool in "
        "your own policy.",
        plane="call",
    ),
    "dangerous_scheme": Control(
        "dangerous_scheme",
        "Non-HTTP URL schemes",
        "Refuses file://, gopher://, dict:// and similar schemes on fetch-style tools.",
        caveat="These read LOCAL files or speak unrelated protocols, so they are a local-file-read "
        "and SSRF primitive rather than a web fetch. Ordinary http/https is untouched. Some of these "
        "URLs already blocked before this control existed — but as deny_shell_execution, which "
        "attributed them to a shell-execution attempt that never happened.",
        plane="call",
    ),
    "ssrf_metadata": Control(
        "ssrf_metadata",
        "Cloud metadata & loopback (SSRF)",
        "Refuses tool calls that reach a cloud instance-metadata endpoint or the pod's own loopback.",
        caveat="Matches on the destination, not the tool name, and resolves the alternate spellings "
        "(169.254.169.254, metadata.google.internal, 2130706433, 0x7f000001, 127.1, localhost) to the "
        "same address. Private RFC1918 ranges are deliberately NOT included: an agent in Kubernetes "
        "reaches in-cluster services on 10.x/172.16-31.x constantly, so blocking those would refuse "
        "ordinary traffic. Scope them yourself with derived.destinations.internal.private if you want "
        "that rule.",
        plane="call",
    ),
    "pii_detection": Control(
        "pii_detection",
        "PII egress",
        "Catches personal data leaving via a tool call.",
        caveat="Narrower than the name suggests: it matches US SSN-shaped values. Email addresses, "
        "phone numbers, dates of birth and passport numbers are NOT detected, so this control on "
        "its own is not sufficient for a customer-data policy.",
        plane="call",
    ),
    "pci_card_numbers": Control(
        "pci_card_numbers",
        "Card numbers (PCI)",
        "Catches payment card numbers in tool parameters, by field name and by value.",
        plane="call",
    ),
    "cross_tenant_access": Control(
        "cross_tenant_access",
        "Cross-tenant access",
        "Catches a call reaching for another tenant's data.",
        plane="call",
    ),
    "chain_depth_limit": Control(
        "chain_depth_limit",
        "Tool-chain depth",
        "Catches runaway tool-calling chains beyond the configured depth.",
        caveat="All five SDK adapters now report call depth, and the SDK's measurement is "
        "authoritative — it wraps tool execution, so a nested call is measurably deeper and the agent "
        "cannot under-report it. Traffic arriving through a sidecar or the MCP proxy is different: a "
        "cross-process PEP can only forward the depth its CALLER claims, so a client that reports 0 "
        "is believed. Trust this control for SDK-instrumented workloads; treat it as advisory for "
        "proxied ones.",
        plane="call",
    ),
    "base64_decoded_threat": Control(
        "base64_decoded_threat",
        "Encoded payloads",
        "Catches threats hidden behind base64, including nested encodings.",
        plane="call",
    ),
    "strict_default_block": Control(
        "strict_default_block",
        "High-risk tool names",
        "Blocks execute_sql outright, plus any tool whose name starts with delete_, drop_, "
        "truncate_, destroy_, wipe_, purge_ or erase_.",
        caveat="Matches on the tool NAME alone, with no regard to arguments — a read-only reporting "
        "tool called delete_candidates_report is blocked. This is the control most likely to need "
        "an exception for a legitimate tool.",
        plane="call",
    ),
    "scope_violation_dangerous_tool": Control(
        "scope_violation_dangerous_tool",
        "Out-of-scope tool use",
        "Records an agent class using a tool outside its expected scope.",
        plane="call",
    ),
    # ── the DISCOVERY plane: what the MCP proxy learned before the model saw the tool ─────────────
    #
    # These read `input.mcp`, which only exists when a call arrived through the Norviq MCP proxy. On
    # an estate with no MCP they are inert — which is why they can ship enforcing without a
    # measurable false-positive surface: there is no legitimate traffic for them to touch. The
    # benign corpus exercises each one anyway, because "inert" is a claim that has to be checked.
    "mcp_definition_drift": Control(
        "mcp_definition_drift",
        "MCP definition changed after approval",
        "The rug pull: an MCP server is serving a tool definition that is not the one an operator "
        "approved. Detected by content hash at discovery, before the model reads the new text.",
        caveat="Escalates rather than blocks, deliberately. Adopting a changed definition is a "
        "legitimate operator action — a server that ships a bug fix changes its description — and "
        "the safe default is a human looking at the diff, not a silently broken agent.",
        plane="discovery",
        surface="mcp",
    ),
    "mcp_definition_never_scanned": Control(
        "mcp_definition_never_scanned",
        "MCP definition never inspected",
        "A tool call arrived for a definition Gate A never read — a stateless client, or a proxy "
        "restarted since discovery.",
        caveat="Escalates rather than blocks: a cold start is ordinary. What is not ordinary is "
        "acting on a definition nobody has read. This exists because every OTHER Gate-A rule tests "
        "for a specific bad state, so a tool in no state at all satisfied none of them and was "
        "allowed — the checks were armed and the thing they protect was never inspected.",
        plane="discovery",
        surface="mcp",
    ),
    "mcp_tool_not_approved": Control(
        "mcp_tool_not_approved",
        "MCP tool awaiting approval",
        "In strict pin mode a newly-seen MCP tool is quarantined until an operator approves its "
        "definition. This refuses the call while it waits.",
        caveat="Only fires when the proxy runs in strict pin mode. Under the default (tofu) a "
        "first-seen definition is pinned and allowed, and CHANGE is what gets enforced.",
        plane="discovery",
        surface="mcp",
    ),
    "mcp_definition_flagged": Control(
        "mcp_definition_flagged",
        "MCP definition scanned as hostile",
        "The definition itself carries instruction-injection shaped text — the tool-poisoning "
        "vector, where the description is the payload and the model reads it before the user has "
        "typed anything.",
        caveat="The scanner is a heuristic and is evadable by construction; it is the discovery-"
        "plane complement to the deterministic call-plane checks, not a replacement for them.",
        plane="discovery",
        surface="mcp",
    ),
    "mcp_answer_carries_secret": Control(
        "mcp_answer_carries_secret",
        "Credential in an MCP answer",
        "A server may answer a call by asking the CLIENT for more input (the 2026-07-28 "
        "input-required pattern). This refuses to send a credential back as that answer.",
        caveat="Depends on the response classifier recognising the value as a secret; a credential "
        "in a shape the classifier does not know is not caught here.",
        plane="response",
        surface="mcp",
    ),
}


def _preset_dir() -> Path | None:
    """Locate the shipped presets, in the repo and in the API/engine images.

    Mirrors `packs._sector_dir()`. The presets are authored in `webhook/presets/` and COPYed into the
    API and engine images at the same path, rather than duplicated under `policies/` — this codebase
    already has one preset maintained in two places (`comprehensive.rego` vs `strict.rego`), and the
    drift guard for that pair only runs under `opa test`, never in-cluster.
    """
    for candidate in (
        Path(__file__).resolve().parents[2] / "webhook" / "presets",  # repo checkout
        Path.cwd() / "webhook" / "presets",  # container WORKDIR
        Path("/app/presets"),  # webhook image layout, if ever run there
    ):
        if candidate.is_dir():
            return candidate
    return None


def preset_source(preset: str) -> str:
    """Read a preset's rego. Raises FileNotFoundError rather than returning "" — an empty module
    would compile to a policy that allows everything, which is not a safe way to fail."""
    directory = _preset_dir()
    if directory is None:
        raise FileNotFoundError("preset directory not found (looked for webhook/presets)")
    path = directory / f"{preset}.rego"
    if not path.is_file():
        raise FileNotFoundError(f"unknown preset: {preset}")
    return path.read_text(encoding="utf-8")


def _split_region(src: str) -> tuple[str, str, str]:
    """Split a preset into (before, controls-region, after)."""
    if CONTROLS_BEGIN not in src or CONTROLS_END not in src:
        raise ValueError(f"preset has no {CONTROLS_BEGIN} / {CONTROLS_END} region")
    bi = src.index(CONTROLS_BEGIN)
    body_start = src.index("\n", bi) + 1
    ei = src.index(CONTROLS_END)
    return src[:bi], src[body_start:ei], src[ei + len(CONTROLS_END) :]


def parse_heads(region: str) -> list[ControlHead]:
    """Lift every registration head out of the CONTROLS region, preserving file order."""
    heads: list[ControlHead] = []
    for line in region.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped in _NEVER_FIRES_LINES:
            continue  # generated placeholder, not a control
        match = _HEAD_RE.match(stripped)
        if match is None or not _one_body(match.group(3)):
            # Loud, not skipped. A head this regex cannot read is a control that would silently
            # disappear from every compiled module — an "off" nobody chose and nobody can see.
            raise ValueError(f"unparsable line in CONTROLS region: {stripped!r}")
        heads.append(ControlHead(match.group(1), match.group(2), match.group(3).strip()))
    return heads


def _one_body(guard: str) -> bool:
    """Whether `guard` — the text between a head's first `{` and its last `}` — is ONE rule body.

    `_HEAD_RE`'s guard is greedy, so `blocks["pii_detection"] { pii_detected } blocks["no_newsletter"]
    { input.tool_name == "send_newsletter" }` on one line read as a single pii_detection head whose
    guard happened to contain a second rule. OPA compiles that line as two rules. Measured with it in a
    chart's CONTROLS region: pii_detection set to Off dropped the whole line from the re-render,
    `covers()` held, and the chart's block/no_newsletter came back allow/default_allow — a rule
    nobody switched off. So the braces must close exactly at the end of the line (braces inside a
    string do not count), and a `#` outside a string, which would comment out the rest, is refused.
    """
    depth, quote, escaped = 0, "", False
    for ch in guard:
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\" and quote == '"':
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in '"`':
            quote = ch
        elif ch == "#":
            return False
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0 and not quote


def controls_for(preset: str) -> list[ControlHead]:
    """Every registration head in a preset."""
    return parse_heads(_split_region(preset_source(preset))[1])


def control_ids(preset: str) -> list[str]:
    """Distinct control ids, in the order the preset registers them."""
    seen: list[str] = []
    for head in controls_for(preset):
        if head.control_id not in seen:
            seen.append(head.control_id)
    return seen


@functools.lru_cache(maxsize=8)
def _authored_sets(preset: str) -> dict[str, frozenset[str]]:
    """control id -> the sets its heads register into, as the preset file authors them."""
    sets: dict[str, set[str]] = {}
    for head in controls_for(preset):
        sets.setdefault(head.control_id, set()).add(head.set_name)
    return {cid: frozenset(names) for cid, names in sets.items()}


def shipped_default(control_id: str, preset: str = "strict") -> Effect:
    """What ONE control does when nobody has set it: what the preset's own heads do.

    A `blocks[...]` or `escalates[...]` head defaults to `deny`, an `audits[...]`-only control to
    `monitor`. That is exactly what the chart's baseline does, because the chart's baseline IS the
    preset file. So an untouched row means the same thing in the console, in a saved controls module
    and in the chart, and saving the controls changes only what the operator changed.

    This was a table in `_CONTROL_COPY`, and it disagreed with the preset: it shipped
    `strict_default_block`, `llm02_data_leakage` and `base64_decoded_threat` at `monitor` while the
    preset authors all three as blocks. Harmless while the chart's baseline and the saved controls were
    both floors (the stricter won); once saved controls superseded the chart's baseline, any save — a
    no-op, a pure tightening — quietly turned those three from block into a record for every class in
    the namespace. Measured on the resolver: execute_sql, get_delete_all_records, and an AWS key
    emailed to an external address went from block to audit on a re-save of one unrelated control.

    To ship a control observing, author its heads as `audits[...]` in the preset. The chart then
    records it too, so the two cannot disagree again. The precision guard still applies to every
    `deny` default (tests/redteam/test_benign_precision.py::test_every_deny_default_is_clean_over_the_corpus).

    A control id the preset does not register gets `DEFAULT_EFFECT`.
    """
    sets = _authored_sets(preset).get(control_id)
    if not sets:
        return DEFAULT_EFFECT
    return "deny" if sets & {"blocks", "escalates"} else "monitor"


def default_effects(preset: str) -> dict[str, Effect]:
    """Every control at ITS shipped default — no longer one global for all of them."""
    return {cid: shipped_default(cid, preset) for cid in control_ids(preset)}


def surface_of(control_id: str) -> Surface:
    """What a control governs — `tool` unless it is declared otherwise.

    Defaults to `tool` so a control added to a preset without a copy entry lands in the section an
    operator expects rather than in a section of its own or in none at all.
    """
    copy = _CONTROL_COPY.get(control_id)
    return copy.surface if copy else "tool"


def plane_of(control_id: str) -> Plane:
    """Which plane a control acts on, for the console's grouping."""
    copy = _CONTROL_COPY.get(control_id)
    return copy.plane if copy else "call"


def normalize_effects(preset: str, effects: dict[str, str] | None) -> dict[str, Effect]:
    """Fill in defaults and reject nonsense.

    An unknown control id is an ERROR rather than ignored: silently dropping it would report success
    for a setting that never took effect, and the operator would believe a control was off when it
    was enforcing.
    """
    known = control_ids(preset)
    # Seeded from each control's OWN shipped default, not the global one. This function is what
    # actually decides the compiled module (`_materialize` -> `compile(preset, normalize_effects(...))`),
    # so seeding it from the global made the per-control defaults inert: `describe()` reported
    # `default_effect: "deny"` beside `effect: "monitor"`, i.e. every enforcing control read as
    # deviating from its own default while nothing enforced. Two homes disagreeing about the same
    # question, which is the defect shape this codebase keeps rediscovering.
    resolved: dict[str, Effect] = {cid: shipped_default(cid, preset) for cid in known}
    for cid, effect in (effects or {}).items():
        if cid not in resolved:
            raise ValueError(f"unknown control for preset {preset!r}: {cid}")
        if effect not in EFFECTS:
            raise ValueError(f"invalid effect {effect!r} for control {cid} (expected one of {EFFECTS})")
        resolved[cid] = effect  # type: ignore[assignment]
    return resolved


def enforced_as(preset: str, control_id: str) -> str:
    """`block` | `escalate` | `audit` — what setting this control to `deny` actually does.

    Read from the PRESET's own heads rather than from a table here, for the reason the shipped-default
    guard gives: the author's expressed severity is a signal, and a second copy of it drifts. A control
    with heads in more than one set reports the strongest, which is what the resolver would pick.
    """
    sets = {h.set_name for h in controls_for(preset) if h.control_id == control_id}
    if "blocks" in sets:
        return "block"
    if "escalates" in sets:
        return "escalate"
    return "audit"


def describe(preset: str, effects: dict[str, str] | None = None) -> list[dict]:
    """The operator-facing control list for GET /baseline/controls."""
    resolved = normalize_effects(preset, effects)
    reasons = _reasons_map(preset_source(preset))
    out: list[dict] = []
    for cid in control_ids(preset):
        copy = _CONTROL_COPY.get(cid)
        out.append(
            {
                "id": cid,
                "title": copy.title if copy else cid.replace("_", " ").title(),
                # Falls back to the preset's own reason text, so a control added to a preset without
                # a copy entry still describes itself rather than showing a bare id.
                "description": copy.description if copy else reasons.get(cid, ""),
                "caveat": copy.caveat if copy else "",
                "effect": resolved[cid],
                # PER CONTROL, not the global. The console renders "Reset to default" and a
                # differs-from-default marker off this, so a single global value made every row claim
                # the same default and the marker was wrong for any control that had its own.
                "default_effect": shipped_default(cid, preset),
                "plane": plane_of(cid),
                "surface": surface_of(cid),
                # WHAT `deny` ACTUALLY DOES for this control, which is not always "block".
                #
                # The compiler preserves a head's original severity: a control the preset registers as
                # `escalates[...]` still escalates when the operator sets it to `deny`. The console
                # rendered one sentence for every row — "call is blocked" — so the two MCP controls
                # that hold a call for a human ADVERTISED a hard denial. An operator reading that
                # would either expect an outage that never comes or decline to enforce a control that
                # would not have broken anything.
                "enforced_as": enforced_as(preset, cid),
            }
        )
    return out


def _reasons_map(src: str) -> dict[str, str]:
    """Best-effort read of the preset's `reasons` table, used only as description fallback."""
    out: dict[str, str] = {}
    for match in re.finditer(r'^\s*\"([A-Za-z0-9_]+)\":\s*\"(.*?)\",?\s*$', src, re.MULTILINE):
        out.setdefault(match.group(1), match.group(2))
    return out


def compile(preset: str, effects: dict[str, str] | None = None) -> str:  # noqa: A001 - domain verb
    """Rebuild a preset with each control set to off / monitor / deny.

    Only the CONTROLS region is rewritten. Everything else — every detector predicate, the resolver,
    the reasons table — is passed through unchanged, which is the entire safety argument for this
    feature: changing what a control DOES cannot change how it DETECTS.
    """
    resolved = normalize_effects(preset, effects)
    rendered = _render(preset_source(preset), resolved)
    log.info(
        "nrvq.api.baseline.compiled",
        preset=preset,
        deny=len([1 for eff in resolved.values() if eff == "deny"]),
        monitor=len([1 for eff in resolved.values() if eff == "monitor"]),
        off=len([1 for eff in resolved.values() if eff == "off"]),
        code="NRVQ-API-7110",
    )
    return rendered


def _render(src: str, resolved: dict[str, Effect]) -> str:
    """The compiled module for preset text `src` with every control at its effect in `resolved`.

    Split out of `compile()` so `covers()` can re-render a stored module from the chart's own text and
    compare byte for byte, without logging a compile that never happened.
    """
    before, region, after = _split_region(src)
    emitted: dict[str, list[str]] = {"blocks": [], "escalates": [], "audits": []}
    for head in parse_heads(region):
        effect = resolved[head.control_id]
        if effect == "off":
            continue
        # `monitor` sends every head for the control to audits[], including one that was originally an
        # escalate. Preserving the escalate/block distinction under monitor would be a distinction
        # without a difference — both proceed — while giving the operator two ways to read one setting.
        #
        # `deny` restores the head's ORIGINAL set, except for a control the preset already registers as
        # an audit. `scope_violation_dangerous_tool` is authored `audits[...]`, so "restore the original
        # set" put it straight back in audits[] and it could never block — while PUT reported it under
        # "enforcing" and GET showed effect="deny". The operator was told twice that it was enforcing
        # while the call went through, which is worse than not offering the setting at all.
        #
        # An audit-authored control promoted to deny becomes a real block. That is what the operator
        # asked for, and the alternative (silently refusing the promotion) is the lie we just removed.
        if effect == "monitor":
            target = "audits"
        elif head.set_name == "audits":
            target = "blocks"
        else:
            target = head.set_name
        emitted[target].append(f'{target}["{head.control_id}"] {{ {head.guard} }}')

    off = sorted(cid for cid, eff in resolved.items() if eff == "off")
    lines: list[str] = [
        "# GENERATED by norviq/api/baseline.py — edit the control effects, not this region.",
        f"{CONTROLS_OFF} {' '.join(off)}".rstrip(),
    ]
    for set_name in ("blocks", "escalates", "audits"):
        rules = emitted[set_name]
        lines.append("")
        if rules:
            lines.extend(rules)
        else:
            lines.append(_NEVER_FIRES.format(set=set_name))
    return f"{before}{CONTROLS_BEGIN}\n" + "\n".join(lines) + f"\n{CONTROLS_END}{after}"


def _off_ids(region: str) -> frozenset[str] | None:
    """The control ids a compiled region records as `off`; None when it carries no record at all."""
    for line in region.splitlines():
        stripped = line.strip()
        if stripped.startswith(CONTROLS_OFF):
            return frozenset(stripped[len(CONTROLS_OFF) :].split())
    return None


def effects_of(compiled: str, chart: str) -> dict[str, Effect] | None:
    """The effect a compiled module gives each control `chart` registers, read back from its region.

    `off` from the CONTROLS_OFF record, `deny` for a control with a block or escalate head, `monitor`
    for one whose heads are all audits. None when the module carries no CONTROLS_OFF record (it was
    compiled before the record existed), or when a chart control is neither recorded off nor present:
    the module then does not say what that control should do. Raises ValueError on an unreadable region.
    """
    _, c_region, _ = _split_region(compiled)
    off = _off_ids(c_region)
    if off is None:
        return None
    present: dict[str, set[str]] = {}
    for head in parse_heads(c_region):
        present.setdefault(head.control_id, set()).add(head.set_name)
    effects: dict[str, Effect] = {}
    for head in parse_heads(_split_region(chart)[1]):
        cid = head.control_id
        if cid in off:
            effects[cid] = "off"
        elif present.get(cid, set()) & {"blocks", "escalates"}:
            effects[cid] = "deny"
        elif present.get(cid):
            effects[cid] = "monitor"
        else:
            return None
    return effects


def covers(compiled: str, chart: str) -> bool:
    """True when `compiled` is exactly what THIS compiler renders from `chart` for some effects.

    The engine asks this before letting a namespace's saved controls (`<ns>:__controls__`) supersede
    the chart's baseline (`<ns>:__baseline__`). Superseding is only honest when the controls module
    is the chart's own module with an effect on every control, so the module's effects are read back
    (`effects_of`) and the chart's own text is re-rendered with them; the two must be byte-identical.
    Anything it cannot read is a `False`, which keeps the chart's baseline as a floor. That one
    comparison refuses:

    * a chart on another preset (`moderate` and `permissive` have no CONTROLS region) or its own rego;
    * a chart control or detector arm the module never saw, and any difference outside the region —
      the controls were compiled from a different preset file than the chart's;
    * a module compiled before CONTROLS_OFF existed, or by any compiler whose output differs from this
      one's — v0.2.5's modules among them, Off or not. The API re-renders every namespace's saved
      controls from their stored effects at startup (baseline_router.rematerialize_controls), so a
      stale module is replaced rather than left deciding.
    """
    try:
        effects = effects_of(compiled, chart)
        if not effects:
            return False
        return _render(chart, effects) == compiled
    except (ValueError, KeyError):
        return False
