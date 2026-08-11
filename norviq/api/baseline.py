# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Baseline controls: the shipped detectors, individually turned on, observed, or off.

A preset used to be all-or-nothing. Installing the chart put 22 block rules in front of every tool
call in every tenant namespace on day one, before the customer had written a policy or seen a single
decision — and one of those rules (`deny_shell_execution`, via the base64 fan-out) fires on roughly
1 in 8 ordinary alphanumeric identifiers. There was no way to keep the detector and stop it dropping
traffic, short of turning the whole preset off.

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

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import structlog

log = structlog.get_logger()

Effect = Literal["off", "monitor", "deny"]
EFFECTS: tuple[str, ...] = ("off", "monitor", "deny")

# Every control ships OBSERVING. Nothing is dropped on a fresh install; the customer sees what WOULD
# be blocked, by which control, and promotes the ones they want once they know the blast radius.
DEFAULT_EFFECT: Effect = "monitor"

CONTROLS_BEGIN = "# >>> CONTROLS-BEGIN"
CONTROLS_END = "# >>> CONTROLS-END"

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
_NEVER_FIRES_RE = re.compile(r"^(blocks|escalates|audits)\[id\]\s*\{\s*false;")


@dataclass(frozen=True, slots=True)
class ControlHead:
    """One registration line lifted out of a preset's CONTROLS region."""

    set_name: str
    control_id: str
    guard: str


@dataclass(frozen=True, slots=True)
class Control:
    """A control as an operator sees it: what it catches, and what it costs to enforce."""

    id: str
    title: str
    description: str
    # Named so the console can warn before promotion. Empty when the control has no known
    # false-positive mode worth calling out.
    caveat: str = ""


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
    ),
    "deny_sql_injection": Control(
        "deny_sql_injection",
        "SQL injection",
        "Catches destructive or injected SQL in any tool's parameters, not just execute_sql — a "
        "renamed tool carrying 'drop table users' is caught too.",
    ),
    "deny_sql_multi_statement": Control(
        "deny_sql_multi_statement",
        "Multi-statement SQL",
        "Catches stacked statements and SQL metacharacters on execute_sql.",
    ),
    "deny_shell_execution": Control(
        "deny_shell_execution",
        "Shell / command execution",
        "Catches shell metacharacters and command-execution patterns in tool parameters.",
        caveat="Highest false-positive rate of any control. It also scans base64-DECODED parameter "
        "values and matches single characters such as '|' in the decoded bytes, so ordinary "
        "alphanumeric identifiers — order ids, tracking codes, session tokens — decode to random "
        "bytes and trip it roughly 1 in 8 times at 16-24 characters. Observe before promoting.",
    ),
    "llm06_excessive_agency": Control(
        "llm06_excessive_agency",
        "Destructive & elevated tools",
        "Blocks tools that delete or destroy, and escalates elevated ones.",
    ),
    "llm02_data_leakage": Control(
        "llm02_data_leakage",
        "Secret egress",
        "Catches credentials and secrets sent to an external sink, on ANY tool name — including "
        "tool names it has never seen.",
    ),
    "llm05_supply_chain": Control(
        "llm05_supply_chain",
        "Supply chain",
        "Catches plugin/script loading from untrusted sources.",
    ),
    "pii_detection": Control(
        "pii_detection",
        "PII egress",
        "Catches personal data leaving via a tool call.",
        caveat="Narrower than the name suggests: it matches US SSN-shaped values. Email addresses, "
        "phone numbers, dates of birth and passport numbers are NOT detected, so this control on "
        "its own is not sufficient for a customer-data policy.",
    ),
    "pci_card_numbers": Control(
        "pci_card_numbers",
        "Card numbers (PCI)",
        "Catches payment card numbers in tool parameters, by field name and by value.",
    ),
    "cross_tenant_access": Control(
        "cross_tenant_access",
        "Cross-tenant access",
        "Catches a call reaching for another tenant's data.",
    ),
    "chain_depth_limit": Control(
        "chain_depth_limit",
        "Tool-chain depth",
        "Catches runaway tool-calling chains beyond the configured depth.",
        caveat="Only LangChain reports call depth today — one adapter of five. Under CrewAI, AutoGen, "
        "LangGraph and Semantic Kernel a nested call reports depth 0, so this control cannot fire "
        "on that traffic even at deny.",
    ),
    "base64_decoded_threat": Control(
        "base64_decoded_threat",
        "Encoded payloads",
        "Catches threats hidden behind base64, including nested encodings.",
    ),
    "strict_default_block": Control(
        "strict_default_block",
        "High-risk tool names",
        "Blocks execute_sql outright, plus any tool whose name starts with delete_, drop_, "
        "truncate_, destroy_, wipe_, purge_ or erase_.",
        caveat="Matches on the tool NAME alone, with no regard to arguments — a read-only reporting "
        "tool called delete_candidates_report is blocked. This is the control most likely to need "
        "an exception for a legitimate tool.",
    ),
    "scope_violation_dangerous_tool": Control(
        "scope_violation_dangerous_tool",
        "Out-of-scope tool use",
        "Records an agent class using a tool outside its expected scope.",
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
        if _NEVER_FIRES_RE.match(stripped):
            continue  # generated placeholder, not a control
        match = _HEAD_RE.match(stripped)
        if match is None:
            # Loud, not skipped. A head this regex cannot read is a control that would silently
            # disappear from every compiled module — an "off" nobody chose and nobody can see.
            raise ValueError(f"unparsable line in CONTROLS region: {stripped!r}")
        heads.append(ControlHead(match.group(1), match.group(2), match.group(3).strip()))
    return heads


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


def default_effects(preset: str) -> dict[str, Effect]:
    """Every control at the shipped default."""
    return {cid: DEFAULT_EFFECT for cid in control_ids(preset)}


def normalize_effects(preset: str, effects: dict[str, str] | None) -> dict[str, Effect]:
    """Fill in defaults and reject nonsense.

    An unknown control id is an ERROR rather than ignored: silently dropping it would report success
    for a setting that never took effect, and the operator would believe a control was off when it
    was enforcing.
    """
    known = control_ids(preset)
    resolved: dict[str, Effect] = {cid: DEFAULT_EFFECT for cid in known}
    for cid, effect in (effects or {}).items():
        if cid not in resolved:
            raise ValueError(f"unknown control for preset {preset!r}: {cid}")
        if effect not in EFFECTS:
            raise ValueError(f"invalid effect {effect!r} for control {cid} (expected one of {EFFECTS})")
        resolved[cid] = effect  # type: ignore[assignment]
    return resolved


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
                "default_effect": DEFAULT_EFFECT,
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
    src = preset_source(preset)
    before, region, after = _split_region(src)
    resolved = normalize_effects(preset, effects)

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

    lines: list[str] = [
        "# GENERATED by norviq/api/baseline.py — edit the control effects, not this region.",
    ]
    for set_name in ("blocks", "escalates", "audits"):
        rules = emitted[set_name]
        lines.append("")
        if rules:
            lines.extend(rules)
        else:
            lines.append(_NEVER_FIRES.format(set=set_name))

    off = sorted(cid for cid, eff in resolved.items() if eff == "off")
    monitored = sorted(cid for cid, eff in resolved.items() if eff == "monitor")
    log.info(
        "nrvq.api.baseline.compiled",
        preset=preset,
        deny=len([1 for eff in resolved.values() if eff == "deny"]),
        monitor=len(monitored),
        off=len(off),
        code="NRVQ-API-7110",
    )
    return f"{before}{CONTROLS_BEGIN}\n" + "\n".join(lines) + f"\n{CONTROLS_END}{after}"
