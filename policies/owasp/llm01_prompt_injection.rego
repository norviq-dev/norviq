# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.owasp.llm01_prompt_injection

import rego.v1

default allow := false
default decision := "allow"

injection_patterns := [
    "ignore previous",
    "ignore above",
    "disregard",
    "forget your instructions",
    "you are now",
    "act as",
    "pretend you",
    "system prompt",
    "jailbreak",
    "dan mode",
    "ignore all previous instructions",
    "override",
]

param_values contains v if {
    v := input.tool_params[_]
    is_string(v)
}

contains_injection if {
    val := param_values[_]
    pattern := injection_patterns[_]
    contains(lower(val), pattern)
}

decision := "block" if contains_injection

allow if decision == "allow"

rule_id := "llm01_prompt_injection" if contains_injection
rule_id := "default_allow" if not contains_injection

reason := "Prompt injection pattern detected in tool parameters" if contains_injection
reason := "Allowed" if not contains_injection
