# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.rate_limiting.burst_detection

import rego.v1

default allow := false
default decision := "allow"

patterns := ["burst", "spike", "rapid"]

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

rule_id := "burst_detection" if detected
rule_id := "default_allow" if not detected

reason := "Policy burst_detection triggered" if detected
reason := "Allowed" if not detected
