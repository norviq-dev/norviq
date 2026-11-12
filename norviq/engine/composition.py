# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Which base policies the console generated as TIGHTEN-ONLY, so the engine composes them that way.

Base tiers (the agent-class policy, the namespace tier, the workload tier) resolve by priority: the
highest priority decides outright. That is right for a policy written to decide, and wrong for one
written only to add blocks. The Visual Builder's "Tighten-only rules" mode and the New Policy composer
both emit a module whose default is `allow` and whose rules can only block, escalate or audit. Its
`allow` means "no rule of mine fired", not "permit this call". Resolved by priority, that allow beat a
lower-priority namespace-tier policy that blocked the call, so a policy labelled tighten-only loosened
the namespace.

A module recognised here is collected as an overlay instead (see `_collect_candidates`): it can make a
decision stricter and never looser, whatever its priority. Treating a module as an overlay can only
remove its ability to loosen, so a wrong positive costs an intended loosening, never a block.

Recognition is from what the generators write, so policies saved before this module existed are covered
without a re-save:

* Visual Builder, rules mode: the embedded graph (`# nrvq-builder-graph/v1:`) says mode "rules" and
  default "allow", and the body still hashes to `# nrvq-builder-hash:`. A body that no longer matches the
  hash was hand-edited; the graph then no longer describes it, so it is not recognised and keeps priority
  semantics, like any hand-written policy.
* New Policy composer: `package norviq.composer.<token>` with `default decision = "allow"`.
* The server's remediation and capability drafts (norviq/api/threat_intent.py): `package
  norviq.remediation.<...>` with `default decision = "allow"`. Each states "TIGHTEN-ONLY ... only ADDS
  denials" in its header, and is applied as a base policy at the baseline's priority when it is not
  applied to a `<class>__remediation__` overlay key.

An allowlist (the builder's allowlist mode, `generate_intent_rego`) is deliberately NOT recognised. It
decides for its scope, and a class allowlist at a higher priority is meant to be able to grant a tool a
namespace-tier allowlist does not. Its header says so rather than calling it tighten-only.
"""

from __future__ import annotations

import base64
import binascii
import functools
import json
import re

import structlog

log = structlog.get_logger()

_GRAPH_LINE = re.compile(r"(?m)^# nrvq-builder-graph/v1: (.+)$")
_HASH_LINE = re.compile(r"(?m)^# nrvq-builder-hash: ([0-9a-f]{8})$")
_BLOCKS_ONLY_PACKAGE = re.compile(r"(?m)^package norviq\.(composer|remediation)\.[A-Za-z0-9_.]+\s*$")
_DEFAULT_ALLOW = re.compile(r'(?m)^default decision = "allow"\s*$')


def fnv1a_hex(text: str) -> str:
    """32-bit FNV-1a over the UTF-8 bytes, as 8 hex digits. Same function as builderCompile.ts `fnv1aHex`."""
    value = 0x811C9DC5
    for byte in text.encode("utf-8"):
        value ^= byte
        value = (value * 0x01000193) & 0xFFFFFFFF
    return f"{value:08x}"


def attached_builder_graph(rego: str) -> dict | None:
    """The builder graph embedded in `rego`, or None when absent, unreadable or detached.

    Detached means the body after the hash line no longer hashes to it: the module was edited by hand
    and the graph no longer describes what it does. Mirrors builderCompile.ts `detachmentStatusOf`.
    """
    graph_match = _GRAPH_LINE.search(rego or "")
    hash_match = _HASH_LINE.search(rego or "")
    if not graph_match or not hash_match:
        return None
    body = rego[hash_match.end() + 1:]
    if fnv1a_hex(body) != hash_match.group(1):
        return None
    try:
        graph = json.loads(base64.b64decode(graph_match.group(1).strip(), validate=True).decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        # The body hashes to its header, so a builder wrote this module, but its graph blob does not
        # decode. Nothing can say what mode it was built in, so it keeps priority semantics. Said out loud
        # because a builder policy labelled tighten-only then composes as a base tier.
        log.warning("nrvq.engine.builder_graph_unreadable", error=type(exc).__name__, code="NRVQ-ENG-2072")
        return None
    return graph if isinstance(graph, dict) else None


@functools.lru_cache(maxsize=512)
def declares_tighten_only(rego: str) -> bool:
    """True when `rego` is a tighten-only module from the Visual Builder, the composer or a remediation draft.

    Cached by source text: it runs once per candidate per evaluation, and a policy's text changes only
    when it is saved.
    """
    if not rego:
        return False
    graph = attached_builder_graph(rego)
    if graph is not None:
        defaults = graph.get("defaults")
        return (
            graph.get("mode") != "allowlist"
            and isinstance(defaults, dict)
            and defaults.get("decision") == "allow"
        )
    return bool(_BLOCKS_ONLY_PACKAGE.search(rego) and _DEFAULT_ALLOW.search(rego))
