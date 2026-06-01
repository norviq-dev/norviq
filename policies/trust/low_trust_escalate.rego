# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.trust.low_trust_escalate

import rego.v1

default allow := false
default decision := "allow"

patterns := ["low_trust", "trust_score", "risk"]

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

rule_id := "low_trust_escalate" if detected
rule_id := "default_allow" if not detected

reason := "Policy low_trust_escalate triggered" if detected
reason := "Allowed" if not detected
