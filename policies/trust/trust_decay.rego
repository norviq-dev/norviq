# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.trust.trust_decay

import rego.v1

default allow := false
default decision := "allow"

patterns := ["decay", "aging", "stale"]

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

decision := "escalate" if detected

allow if decision == "allow"

rule_id := "trust_decay" if detected
rule_id := "default_allow" if not detected

reason := "Policy trust_decay triggered" if detected
reason := "Allowed" if not detected
