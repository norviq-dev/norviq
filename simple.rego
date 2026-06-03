package norviq.strict

default decision = "allow"
default rule_id = "default_allow"
default reason = "Allowed"

decision = "block" {
    input.tool_name == "execute_sql"
    contains(lower(input.tool_params.query), "drop table")
}

rule_id = "deny_sql_injection" {
    input.tool_name == "execute_sql"
    contains(lower(input.tool_params.query), "drop table")
}

reason = "SQL injection blocked" {
    input.tool_name == "execute_sql"
    contains(lower(input.tool_params.query), "drop table")
}
