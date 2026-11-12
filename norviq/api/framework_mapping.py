# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The one rule <-> technique/control mapping that Compliance and Red Team both read.

The shipped files ``policies/mitre_mapping.json`` (MITRE ATLAS) and ``policies/owasp_llm_mapping.json``
(OWASP LLM Top 10, 2025) map each technique or control to the rule_ids that enforce it. Compliance
reads them forwards (technique -> rules present in the loaded rego). Red Team reads them backwards:
an attack is credited to every technique and control whose ``policies`` list contains the rule the
attack expects to fire. Neither side keeps a table of its own.

Red Team used to carry a literal technique per attack and derived the OWASP id from the attack
category's enum name. Nothing compared either to these files, so prompt-injection attacks were
scored under AML.T0048 External Harms (out of scope here), destructive-tool attacks under AML.T0051
Prompt Injection, and the supply-chain attacks under LLM05:2025, a 2023 number that now names
Improper Output Handling.

A rule no technique lists is unmapped. Red Team reports that as unmapped rather than inventing a
technique or using the bare id as its name.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

import structlog

log = structlog.get_logger()

FRAMEWORK_FILES = {"atlas": "mitre_mapping.json", "owasp": "owasp_llm_mapping.json"}


@lru_cache(maxsize=len(FRAMEWORK_FILES))
def load_mapping(framework: str = "atlas") -> dict:
    """A framework's technique -> {name, scope, policies, ...} table, read once from disk.

    An unknown framework reads the ATLAS file, which is what the Compliance routes have always done.
    """
    filename = FRAMEWORK_FILES.get(framework, FRAMEWORK_FILES["atlas"])
    for base in (Path(__file__).resolve().parents[2] / "policies", Path.cwd() / "policies"):
        path = base / filename
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    log.warning("nrvq.api.mitre.mapping_missing", framework=framework, code="NRVQ-API-7070-ERR")
    return {}


@lru_cache(maxsize=len(FRAMEWORK_FILES))
def _rule_index(framework: str) -> dict[str, tuple[tuple[str, str], ...]]:
    """rule_id -> ((technique_id, name), ...), in the mapping file's order."""
    index: dict[str, list[tuple[str, str]]] = {}
    for tid, info in load_mapping(framework).items():
        if not isinstance(info, dict):
            continue
        name = str(info.get("name") or "")
        for rule in info.get("policies") or []:
            entries = index.setdefault(str(rule), [])
            if all(t != tid for t, _ in entries):
                entries.append((tid, name))
    return {rule: tuple(entries) for rule, entries in index.items()}


def techniques_for_rule(rule_id: str | None, framework: str = "atlas") -> list[tuple[str, str]]:
    """Every (technique_id, name) whose ``policies`` list contains ``rule_id``. Empty when none does."""
    if not rule_id:
        return []
    return list(_rule_index(framework).get(rule_id, ()))


# ── tool name -> rule -> technique ────────────────────────────────────────────────────────────────
# The attack graph, the threat-path inspector and the capability registry name a technique for a TOOL,
# not for a rule that fired. Each kept its own tool -> technique table, and none of them agreed with
# Red Team: delete_record and drop_table were AML.T0048 External Harms (out of scope in the ATLAS table)
# while Red Team scored the same tools' attacks (EA-001, EA-003) under AML.T0053, where the table lists
# llm06_excessive_agency. send_email was AML.T0040, ML Model Inference API Access.
#
# So a tool is resolved to the baseline rule that guards it, and the technique comes from the table
# through that rule, the way Red Team does it. The sets below are the NAME-keyed sets of
# comprehensive.rego; tests/api/test_redteam_compliance_mapping.py reads them back out of the rego so
# the two cannot drift. A tool none of them names resolves to no rule and therefore no technique.

SUPPLY_CHAIN_TOOLS = frozenset({"load_plugin", "download_script", "eval", "install_package"})
DESTRUCTIVE_TOOLS = frozenset({"delete_record", "drop_table", "truncate"})
DESTRUCTIVE_NAME_TOKENS = frozenset({"delete", "drop", "truncate", "destroy", "wipe", "purge", "erase"})
ELEVATED_TOOLS = frozenset({"modify_config", "grant_access"})
EXEC_NAME_TOKENS = frozenset({
    "exec", "shell", "bash", "sh", "zsh", "command", "cmd", "spawn", "subprocess", "system", "eval",
    "terminal", "console",
})
SQL_TOOLS = frozenset({"execute_sql"})
EXTERNAL_TOOLS = frozenset({"send_email", "post_webhook", "upload_file"})
SECRET_READ_TOOLS = frozenset({"read_env", "getenv", "get_secret", "read_secret", "fetch_secret"})
EGRESS_PREFIXES = (
    "send_", "post_", "upload_", "publish_", "export_", "http_", "fetch_", "sync_to_", "push_to_", "put_",
    "s3_", "call_", "notify_", "smtp",
)
EGRESS_ACTION_TOKENS = frozenset({
    "send", "post", "upload", "publish", "forward", "relay", "dispatch", "share", "transmit", "deliver",
    "broadcast", "notify", "emit", "push", "webhook", "exfil", "exfiltrate", "leak", "smtp", "sms", "egress",
    "outbound",
})

# comprehensive.rego's `name_split_map`: camelCase and the separators it lists become `_`.
_NAME_SPLIT = re.compile(r"(?=[A-Z])|[-.:/ \t,+|\\]")


def _name_tokens(tool_name: str) -> set[str]:
    return {t.lower() for part in _NAME_SPLIT.split(tool_name) for t in part.split("_") if t}


def rule_for_tool(tool_name: str | None) -> str | None:
    """The baseline rule that guards ``tool_name``, judged by its name alone, or None.

    The rules a name trips by itself come first (supply chain, then destructive or elevated tools,
    in the order the rego reports them). Then the rule that guards the tool's kind of risk when its
    arguments carry the attack: shell execution, SQL, egress of secrets.
    """
    if not tool_name:
        return None
    name = tool_name.lower()
    tokens = _name_tokens(tool_name)
    if name in SUPPLY_CHAIN_TOOLS:
        return "llm05_supply_chain"
    if name in DESTRUCTIVE_TOOLS or name in ELEVATED_TOOLS or tokens & DESTRUCTIVE_NAME_TOKENS:
        return "llm06_excessive_agency"
    if tokens & EXEC_NAME_TOKENS:
        return "deny_shell_execution"
    if name in SQL_TOOLS:
        return "deny_sql_injection"
    if (
        name in EXTERNAL_TOOLS
        or name in SECRET_READ_TOOLS
        or name.startswith(EGRESS_PREFIXES)
        or "webhook" in name
        or "exfil" in name
        or tokens & EGRESS_ACTION_TOKENS
    ):
        return "llm02_data_leakage"
    return None


def techniques_for_tool(tool_name: str | None, framework: str = "atlas") -> list[tuple[str, str]]:
    """Every (technique_id, name) the table lists the rule guarding ``tool_name`` under."""
    return techniques_for_rule(rule_for_tool(tool_name), framework)
