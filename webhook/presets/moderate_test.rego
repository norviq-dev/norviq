# Conflict guard: the moderate preset resolves decision/rule_id/reason from partial-set triggers +
# a resolver, so an input that matches BOTH triggers (execute_sql carrying "drop") must bind exactly
# one decision (block > escalate) instead of raising eval_conflict_error. Run:
#   opa test --v0-compatible moderate.rego moderate_test.rego
package norviq.presets.moderate_test

import data.norviq.presets.moderate

# Previously-conflicting input: execute_sql + "drop" fired both complete rules -> engine error.
# Block wins deterministically now.
test_conflicting_input_blocks {
  moderate.decision == "block" with input as {"tool_name": "execute_sql", "tool_params": {"query": "DROP TABLE users"}}
  moderate.rule_id == "moderate_drop_block" with input as {"tool_name": "execute_sql", "tool_params": {"query": "DROP TABLE users"}}
  moderate.reason == "Moderate preset blocked destructive SQL" with input as {"tool_name": "execute_sql", "tool_params": {"query": "DROP TABLE users"}}
}

# Escalate-only: execute_sql with a benign query.
test_execute_sql_without_drop_escalates {
  moderate.decision == "escalate" with input as {"tool_name": "execute_sql", "tool_params": {"query": "SELECT 1"}}
  moderate.rule_id == "moderate_escalate" with input as {"tool_name": "execute_sql", "tool_params": {"query": "SELECT 1"}}
}

# Block-only: destructive SQL carried by a non-execute_sql tool.
test_drop_in_other_tool_blocks {
  moderate.decision == "block" with input as {"tool_name": "run_report", "tool_params": {"query": "drop table sales"}}
}

# Default allow.
test_benign_allows {
  moderate.decision == "allow" with input as {"tool_name": "search_kb", "tool_params": {"q": "quarterly report"}}
}
