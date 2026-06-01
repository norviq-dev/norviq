# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.industry.finance.audit_all_transactions

import rego.v1

default allow := false
default decision := "allow"

patterns := ["transaction", "transfer", "payment"]

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

rule_id := "audit_all_transactions" if detected
rule_id := "default_allow" if not detected

reason := "Policy audit_all_transactions triggered" if detected
reason := "Allowed" if not detected
