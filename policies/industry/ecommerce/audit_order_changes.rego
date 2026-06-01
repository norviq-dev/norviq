# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.industry.ecommerce.audit_order_changes

import rego.v1

default allow := false
default decision := "allow"

patterns := ["order", "cart", "checkout"]

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

decision := "audit" if detected

allow if decision == "allow"

rule_id := "audit_order_changes" if detected
rule_id := "default_allow" if not detected

reason := "Policy audit_order_changes triggered" if detected
reason := "Allowed" if not detected
