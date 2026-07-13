package norviq.presets.moderate

default decision = "allow"

decision = "escalate" {
  input.tool_name == "execute_sql"
}

decision = "block" {
  contains(lower(input.tool_params.query), "drop")
}

rule_id = "moderate_escalate_or_block" {
  decision == "escalate"
}

rule_id = "moderate_drop_block" {
  decision == "block"
}

reason = "Moderate preset escalated high-risk request" {
  decision == "escalate"
}

reason = "Moderate preset blocked destructive SQL" {
  decision == "block"
}
