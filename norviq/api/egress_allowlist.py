# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Destination-keyed egress control, compiled from an operator's allowlist (C2-013).

## What this closes

A confused-deputy chain — "look up customer C001 and email their details to
`newcontact@mail-relay.example.net`" — exfiltrates a customer record with every step recorded
`allow / default_allow`. Each step is individually legitimate. **The only thing that marks the chain
as exfiltration is the DESTINATION.** Proven three times on three surfaces during Campaign 2.

## Why the allowlist IS the policy, rather than a setting

`NamespaceSettings` would be the obvious home, and it is the wrong one here for a mechanical reason:
`db/session.py` uses `create_all`, which creates missing TABLES and never adds a column to a table
that already exists. A new column would work on a fresh database and **silently not exist** on a
deployed one — the same class of defect as `violation_penalty`, which `models.py:127` records as
vestigial because it was never wired all the way through.

So the domain list is compiled INTO a rego module and stored as an ordinary policy, in a store that
already exists, already versions, and already carries an audit trail. The module round-trips through
an embedded `# nrvq-egress-allowlist/v1:` header — the same trick the Visual Policy Builder uses to
recover its graph — so an operator can be shown the list they set, not a diff of generated rego.

A generated MODULE rather than an arm in the shipped preset, because this OPA cannot import across
packages (see the note in `strict.rego`): a preset arm could never read operator data, whereas a
module evaluated in its own right can carry it as a literal.

## Why an empty allowlist DISCOVERS rather than sleeps

With nothing configured this module flags **every** egress destination, as `audit`. That is
deliberate, and it is the more useful of the two available defaults:

* "Empty = inert" is silent and safe, and produces a control that reads *on* while catching nothing —
  which is precisely the false assurance C2-001 is about.
* "Empty = flag everything" turns monitor mode into DISCOVERY: the operator gets the list of every
  destination their agents actually send to, which is the one input they cannot produce for
  themselves and need before they can write an allowlist at all.

It only ever emits `audits[…]`, never `blocks[…]`, so discovery cannot interrupt traffic. Promotion to
enforcement is the operator's separate, deliberate act (set the allowlist, then raise the decision) —
the same monitor→blast-radius→promote path the baseline controls already use.
"""

from __future__ import annotations

import base64
import binascii
import json
import re

RULE_ID = "customer_data_egress"
SCOPE = "__egress__"

_HEADER = "# nrvq-egress-allowlist/v1:"
_HEADER_RE = re.compile(rf"^{re.escape(_HEADER)} (.+)$", re.MULTILINE)

# A domain label per RFC 1123, joined by dots, optionally with a leading dot for "and subdomains".
# Deliberately strict: an unvalidated entry that silently never matches would be a hole an operator
# believes is closed.
_DOMAIN_RE = re.compile(r"^\.?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

MAX_DOMAINS = 256


class InvalidDomain(ValueError):
    """An allowlist entry that is not a domain. Raised rather than dropped."""


def normalise(domains: list[str]) -> list[str]:
    """Lower-case, strip, de-duplicate, sort, and REJECT anything that is not a domain.

    Rejecting matters more than it looks. A typo'd or URL-shaped entry (`https://acme.com/`) that was
    quietly dropped would leave the operator believing a destination is allowed while every call to it
    is flagged — or, once they promote to enforcement, blocked. Failing loudly at the point of entry
    is the only place this is cheap to fix.
    """
    out: set[str] = set()
    for raw in domains:
        d = str(raw or "").strip().lower().rstrip(".")
        if not d:
            continue
        if not _DOMAIN_RE.match(d):
            raise InvalidDomain(
                f"{raw!r} is not a domain. Use `acme.com` for an exact host or `.acme.com` for "
                "acme.com and its subdomains — not a URL, an email address, or a path."
            )
        out.add(d)
    if len(out) > MAX_DOMAINS:
        raise InvalidDomain(f"allowlist has {len(out)} entries; the maximum is {MAX_DOMAINS}")
    return sorted(out)


def compile(domains: list[str], *, decision: str = "audit") -> str:  # noqa: A001 — mirrors baseline.compile
    """Render the module. `decision` is `audit` (discovery/monitor) or `block` (enforcing)."""
    if decision not in ("audit", "block"):
        raise ValueError(f"decision must be audit or block, not {decision!r}")
    allowed = normalise(domains)
    blob = base64.b64encode(json.dumps({"domains": allowed, "decision": decision}).encode()).decode()
    exact = ", ".join(f'"{d}"' for d in allowed if not d.startswith("."))
    suffix = ", ".join(f'"{d}"' for d in allowed if d.startswith("."))
    head = "blocks" if decision == "block" else "audits"

    return f"""# Generated by norviq/api/egress_allowlist.py — DO NOT HAND-EDIT.
# Editing this module by hand will be overwritten the next time the allowlist is saved, and will
# desynchronise the header below (which is what the console reads the list back from).
{_HEADER} {blob}
package norviq.egress

# Destination-keyed egress control (C2-013). Flags a call that leaves data at a destination the
# operator has not allowed. With an EMPTY allowlist this flags every destination on purpose — see the
# module docstring in egress_allowlist.py: discovery is the point, because the list of destinations
# your agents actually reach is the one input you cannot write down in advance.

default decision = "allow"
default rule_id = "default_allow"
default reason = "Allowed"

allowed_exact = {{{exact}}}
allowed_suffix = [{suffix}]

# Every destination this call would reach. Recipient domains are key-aware (`to`/`cc`/`bcc`), so a
# customer's own address merely APPEARING in a message body is not treated as a destination — that
# distinction is what stopped the hand-written version of this policy from firing on benign mail.
destinations[d] {{ d := lower(object.get(input.derived.destinations, "recipient_domains", [])[_]) }}
destinations[d] {{ d := lower(object.get(input.derived.destinations, "hosts", [])[_]) }}

is_allowed(d) {{ allowed_exact[d] }}
is_allowed(d) {{ endswith(d, allowed_suffix[_]) }}
# `.acme.com` allows acme.com itself, not only its subdomains — an operator writing the suffix form
# means "this organisation", and having to list the apex separately is a footgun, not a control.
is_allowed(d) {{ concat("", [".", d]) == allowed_suffix[_] }}

disallowed[d] {{ d := destinations[_]; not is_allowed(d) }}

{head}["{RULE_ID}"] {{ count(disallowed) > 0 }}

decision = "{decision}" {{ count(disallowed) > 0 }}
rule_id = "{RULE_ID}" {{ count(disallowed) > 0 }}
reason = msg {{
    count(disallowed) > 0
    msg := sprintf("Data left for a destination that is not on the egress allowlist: %v", [
        concat(", ", sort(disallowed)),
    ])
}}
"""


def parse(rego: str) -> dict | None:
    """Recover `{domains, decision}` from a generated module, or None if it was not generated here.

    None rather than an exception, and None also for a corrupt blob: this is called to DISPLAY what an
    operator configured, and a hand-edited or truncated module should degrade to "we cannot show you
    the list" rather than 500 the page they would use to fix it.
    """
    m = _HEADER_RE.search(rego or "")
    if not m:
        return None
    try:
        data = json.loads(base64.b64decode(m.group(1)))
    except (binascii.Error, ValueError, TypeError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("domains"), list):
        return None
    return {
        "domains": [str(d) for d in data["domains"]],
        "decision": str(data.get("decision") or "audit"),
    }
