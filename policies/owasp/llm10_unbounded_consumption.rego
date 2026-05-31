# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.owasp.llm10_unbounded_consumption

import rego.v1

default allow := false
default decision := "allow"

max_calls_per_session := 100
burst_threshold := 20

over_session_limit if input.call_count > max_calls_per_session

over_burst if {
    input.call_count > burst_threshold
    input.trust_score < 0.5
}

decision := "block" if over_session_limit
decision := "escalate" if { over_burst; not over_session_limit }

allow if decision == "allow"

rule_id := "llm10_session_limit" if over_session_limit
rule_id := "llm10_burst_low_trust" if { over_burst; not over_session_limit }
rule_id := "default_allow" if { not over_session_limit; not over_burst }

reason := sprintf("Session limit exceeded: %d calls (max %d)", [input.call_count, max_calls_per_session]) if over_session_limit
reason := "Burst detected from low-trust agent" if { over_burst; not over_session_limit }
reason := "Allowed" if { not over_session_limit; not over_burst }
