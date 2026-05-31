# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.trust.frozen_agent_block

import rego.v1

default allow := false
default decision := "allow"

is_frozen if input.trust_score == 0

decision := "block" if is_frozen

allow if decision == "allow"

rule_id := "frozen_agent_block" if is_frozen
rule_id := "default_allow" if not is_frozen

reason := "Agent trust is frozen (0.0) - all tool calls blocked until manual review" if is_frozen
reason := "Allowed" if not is_frozen
