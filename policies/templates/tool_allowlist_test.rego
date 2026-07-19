# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.guardrail.tool_allowlist_test

import data.norviq.guardrail.tool_allowlist as g

test_listed_tool_allows {
    g.decision == "allow" with input as {"tool_name": "search_kb", "tool_params": {"q": "x"}}
    g.rule_id == "tool_allowlisted" with input as {"tool_name": "search_kb", "tool_params": {}}
}

# A benign out-of-scope tool (the execute_sql SELECT case) -> escalate, not silent allow
test_unlisted_tool_escalates {
    g.decision == "escalate" with input as {"tool_name": "execute_sql", "tool_params": {"query": "SELECT 1"}}
    g.rule_id == "tool_not_in_allowlist" with input as {"tool_name": "execute_sql", "tool_params": {}}
}

test_unlisted_run_query_escalates {
    g.decision == "escalate" with input as {"tool_name": "run_query", "tool_params": {}}
}

# homoglyph parity: a confusable-folded listed name is still recognized as allowed
test_homoglyph_listed_allows {
    g.decision == "allow" with input as {"tool_name": "ѕearch_kb", "tool_name_normalized": "search_kb", "tool_params": {}}
}
