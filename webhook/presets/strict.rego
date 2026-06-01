package norviq.presets.strict

default decision = "allow"

decision = "block" {
  input.tool_name == "execute_sql"
}

decision = "block" {
  startswith(lower(input.tool_name), "delete_")
}

decision = "block" {
  startswith(lower(input.tool_name), "drop_")
}

decision = "block" {
  startswith(lower(input.tool_name), "truncate_")
}

decision = "block" {
  startswith(lower(input.tool_name), "destroy_")
}

rule_id = "strict_default_block" {
  decision == "block"
}

rule_id = "strict_default_allow" {
  decision == "allow"
}

reason = "Strict preset blocked high-risk tool usage" {
  decision == "block"
}

reason = "Strict preset allowed low-risk tool usage" {
  decision == "allow"
}
