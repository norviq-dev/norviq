# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.rate_limiting.daily_quota

import rego.v1

default allow := false
default decision := "allow"

patterns := ["daily_quota", "daily_limit", "day_cap"]

detected if {
    p := patterns[_]
    contains(lower(input.tool_name), lower(p))
}

detected if {
    v := input.tool_params[_]
    is_string(v)
    p := patterns[_]
    contains(lower(v), lower(p))
}

decision := "block" if detected

allow if decision == "allow"

rule_id := "daily_quota" if detected
rule_id := "default_allow" if not detected

reason := "Policy daily_quota triggered" if detected
reason := "Allowed" if not detected
