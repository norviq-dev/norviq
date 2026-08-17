# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The two MCP controls that need the customer's own server registry.

The other five MCP controls read only `input.mcp.*` and are ordinary heads in the preset's CONTROLS
region. These two cannot be: "is this server registered" and "may we write through it" are questions
about a PER-NAMESPACE LIST an operator maintains in the console, and there is no channel that gets a
list into the preset.

WHY NOT THE OBVIOUS THINGS, since both look easier than this:

  * OPA data documents are out. The runtime is a long-lived `opa run --server` and the client has
    exactly two write verbs, both `/v1/policies` (`norviq/engine/opa_client.py`); queries POST
    `{"input": ...}` only. Nothing writes `/v1/data`, there are no bundles, and every policy is
    package-isolated in `norviq.managed.<key>` so modules cannot import across packages. Adding data
    documents is a new subsystem with a new failure mode — module compiles, data missing — which is
    precisely the silent kind.
  * Substituting into the preset body is out. `baseline.compile()` treats everything outside the
    CONTROLS region as byte-identical passthrough, and `tests/api/test_baseline_compiler.py` asserts
    that literally. It is the basis of the module's safety argument: changing what a control DOES
    cannot change how it DETECTS.

So the list is compiled into rego SET LITERALS in a sibling module on its own reserved scope, exactly
as `norviq/api/egress_allowlist.py` does for egress domains.

THE WARNING FROM THAT PRECEDENT, which is why the router ships in the same change: `egress_allowlist`
has a complete compiler and engine-side collection and **no router**. Its only importer is its own
test, so the feature has never been reachable by a customer. A control that reads a list nobody can
populate is the same shape as no control at all.

DEFAULT POSTURE. With an EMPTY registry both controls are INERT — not "everything is unregistered".
That is the opposite of the egress module's discovery-first choice, and deliberately so: an empty
egress allowlist flags destinations, which is informative and interrupts nothing, whereas an empty
server registry would flag every MCP call on a fresh install and the first thing an operator would do
is switch the control off. The registry populates itself as servers are discovered, and it is the
operator REGISTERING one that gives the control something to say.
"""

from __future__ import annotations

import base64
import json
import re

SCOPE = "__mcp__"
RULE_UNREGISTERED = "mcp_unregistered_server"
RULE_UNAPPROVED_WRITE = "mcp_unapproved_write_server"

_HEADER = "# nrvq-mcp-registry/v1:"
_HEADER_RE = re.compile(rf"^{re.escape(_HEADER)} (.+)$", re.MULTILINE)

#: A server id is operator-chosen and PEP-reported. Validated to the same shape the API column
#: accepts, so an entry that could never match is refused at the point of entry rather than silently
#: leaving a hole the operator believes is closed.
_SERVER_RE = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")

MAX_SERVERS = 512


class InvalidServerId(ValueError):
    """A registry entry that cannot be a server id. Raised rather than dropped."""


def normalise(server_ids: list[str]) -> list[str]:
    """Strip, de-duplicate, sort, and REJECT anything that is not a server id.

    NOT lower-cased, unlike the egress domains: a domain is case-insensitive by specification and a
    server id is an arbitrary operator-chosen string that the PEP reports verbatim. Folding case here
    would make `Reporting-KB` in the console silently fail to match `reporting-kb` on the wire — a
    control that looks configured and matches nothing.
    """
    out: set[str] = set()
    for raw in server_ids:
        s = str(raw or "").strip()
        if not s:
            continue
        if not _SERVER_RE.match(s):
            raise InvalidServerId(
                f"{raw!r} is not a server id. Use the `--server-id` the proxy was started with — "
                "letters, digits, dot, underscore, colon or hyphen, up to 255 characters."
            )
        out.add(s)
    if len(out) > MAX_SERVERS:
        raise InvalidServerId(f"registry has {len(out)} servers; the maximum is {MAX_SERVERS}")
    return sorted(out)


def compile(  # noqa: A001 — mirrors baseline.compile and egress_allowlist.compile
    registered: list[str],
    writable: list[str],
    *,
    unregistered_decision: str = "audit",
    write_decision: str = "block",
) -> str:
    """Render the module from the namespace's registry.

    `registered` is every server an operator has said belongs here; `writable` is the subset that may
    be written through. `writable` is intersected with `registered` rather than trusted as given —
    a server that is writable but not registered is a state the API cannot produce, and honouring it
    here would create a second, contradictory answer to "is this server allowed at all".

    The two decisions default differently on purpose. An unregistered server AUDITS: registration is
    housekeeping that lags reality, and blocking on it would break an estate every time somebody
    stands up a new integration before telling the console. An unapproved WRITE blocks: the operator
    has already said which servers may be written through, so a write anywhere else is a statement
    about an integration they have considered and declined.
    """
    for name, value in (("unregistered_decision", unregistered_decision),
                        ("write_decision", write_decision)):
        if value not in ("audit", "block"):
            raise ValueError(f"{name} must be audit or block, not {value!r}")

    known = normalise(registered)
    write_ok = [s for s in normalise(writable) if s in set(known)]
    blob = base64.b64encode(json.dumps({
        "registered": known, "writable": write_ok,
        "unregistered_decision": unregistered_decision, "write_decision": write_decision,
    }).encode()).decode()

    known_lit = ", ".join(f'"{s}"' for s in known)
    write_lit = ", ".join(f'"{s}"' for s in write_ok)
    unreg_head = "blocks" if unregistered_decision == "block" else "audits"
    write_head = "blocks" if write_decision == "block" else "audits"

    return f"""# Generated by norviq/api/mcp_controls.py — DO NOT HAND-EDIT.
# Hand edits are overwritten the next time a server decision is saved, and desynchronise the header
# below, which is what the console reads the registry back from.
{_HEADER} {blob}
package norviq.mcp_registry

# The two MCP controls that need the customer's own list. The other five read only `input.mcp.*` and
# live in the preset's CONTROLS region.
#
# `input.mcp` is PEP-REPORTED. It is a POLICY input and never a TRUST input: nothing here decides WHO
# is calling. Identity comes from the attested SVID and is never read from an MCP message.

default decision = "allow"
default rule_id = "default_allow"
default reason = "Allowed"

registered_servers = {{{known_lit}}}
writable_servers = {{{write_lit}}}

# Only ever true for a call that CAME THROUGH the MCP proxy. Every other call in the estate — SDK,
# sidecar, webhook — has no `input.mcp` and is untouched by this module.
_is_mcp {{ input.mcp.server != "" }}

# INERT ON AN EMPTY REGISTRY. Not "everything is unregistered": a fresh install would then flag every
# MCP call, and the first thing an operator would do is switch the control off. The registry fills as
# servers are discovered; registering one is what gives this control something to say.
_registry_populated {{ count(registered_servers) > 0 }}

_unregistered {{
    _is_mcp
    _registry_populated
    not registered_servers[input.mcp.server]
}}

# A write through a server the operator did not mark writable. `derived.verb` is the engine's own
# classifier, so this agrees with every other verb-keyed rule in the product rather than re-deriving
# "is this a write" from the tool name. `unknown` is excluded: the classifier saying "I cannot tell"
# is not evidence of a write, and treating it as one would refuse ordinary reads it failed to label.
_unapproved_write {{
    _is_mcp
    _registry_populated
    registered_servers[input.mcp.server]
    not writable_servers[input.mcp.server]
    input.derived.verb != "read"
    input.derived.verb != "unknown"
}}

{unreg_head}["{RULE_UNREGISTERED}"] {{ _unregistered }}
{write_head}["{RULE_UNAPPROVED_WRITE}"] {{ _unapproved_write }}

decision = "{unregistered_decision}" {{ _unregistered }}
rule_id = "{RULE_UNREGISTERED}" {{ _unregistered }}
reason = msg {{
    _unregistered
    msg := sprintf("MCP server %v is not registered for this namespace", [input.mcp.server])
}}

decision = "{write_decision}" {{ _unapproved_write; not _unregistered }}
rule_id = "{RULE_UNAPPROVED_WRITE}" {{ _unapproved_write; not _unregistered }}
reason = msg {{
    _unapproved_write
    not _unregistered
    msg := sprintf("writes are not permitted through MCP server %v", [input.mcp.server])
}}
"""


def parse(rego: str) -> dict | None:
    """Recover the registry a generated module was built from, or None if it was not generated here.

    None rather than an exception, and None also for a corrupt blob: this is called to DISPLAY what an
    operator configured, and a hand-edited or truncated module should degrade to "we cannot show you
    the registry" rather than 500 the page they would use to fix it.
    """
    m = _HEADER_RE.search(rego or "")
    if not m:
        return None
    try:
        data = json.loads(base64.b64decode(m.group(1)))
    except Exception:  # noqa: BLE001 — a corrupt header is a display problem, not an error
        return None
    return data if isinstance(data, dict) else None
