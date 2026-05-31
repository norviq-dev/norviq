# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.presets.moderate

import rego.v1
import data.norviq.owasp.llm01_prompt_injection
import data.norviq.owasp.llm06_excessive_agency
import data.norviq.data_protection.cross_tenant_access
import data.norviq.tool_safety.deny_sql_injection
import data.norviq.trust.frozen_agent_block

default allow := false
default decision := "allow"

has_block if llm01_prompt_injection.decision == "block"
has_block if cross_tenant_access.decision == "block"
has_block if deny_sql_injection.decision == "block"
has_block if frozen_agent_block.decision == "block"

has_escalate if llm06_excessive_agency.decision != "allow"

decision := "block" if has_block
decision := "escalate" if {
    not has_block
    has_escalate
}

allow if decision == "allow"
rule_id := "moderate_preset"
reason := "Moderate preset evaluated"
