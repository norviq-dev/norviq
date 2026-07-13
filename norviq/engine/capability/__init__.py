# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Source-capability model: what verbs a data SOURCE exposes, joined against grants / observed
traffic / policy coverage to classify each verb as defended / undefended / dormant."""

from norviq.engine.capability.source_registry import (
    CapabilityStatus,
    SourceClass,
    Verb,
    VerbFinding,
    classify_source,
    classify_tool,
    default_risk_of_verb,
    defense_meta,
    mutating_verbs_of,
    source_type_of,
    verb_display,
    verb_fragments,
    verb_of_tool,
    verb_risk,
    worst_open_verb,
)

__all__ = [
    "CapabilityStatus",
    "SourceClass",
    "Verb",
    "VerbFinding",
    "classify_source",
    "classify_tool",
    "default_risk_of_verb",
    "defense_meta",
    "mutating_verbs_of",
    "source_type_of",
    "verb_display",
    "verb_fragments",
    "verb_of_tool",
    "verb_risk",
    "worst_open_verb",
]
