# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.rate_limiting.session_limit

import rego.v1

default allow := false
default decision := "allow"

patterns := ["session_limit", "max_session", "quota"]

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

rule_id := "session_limit" if detected
rule_id := "default_allow" if not detected

reason := "Policy session_limit triggered" if detected
reason := "Allowed" if not detected
