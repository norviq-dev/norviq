package norviq.custom

# DENY-BY-DEFAULT allowlist — "only these SQL statements may run; block everything else."
#
# Reads input.derived so the rule cannot be defeated by param renaming (query vs sql), tool renaming
# (execute_sql vs run_report), or formatting (case, whitespace, trailing semicolon).

default decision = "block"
default rule_id = "sql_allowlist_default_deny"
default reason = "query is not on the approved allowlist"

allowed_sql = {
    "select * from orders",
    "select id, status from shipments",
}

# Any statement carried by this call that is NOT approved.
unapproved_statement {
    s := input.derived.sql_statements[_]
    not allowed_sql[s]
}

# Non-SQL tools are outside this policy's scope — fall through to the platform baseline.
decision = "allow" {
    input.derived.tool_kind != "sql"
}
# A SQL tool is allowed only when it carries at least one statement and NONE are unapproved.
decision = "allow" {
    input.derived.tool_kind == "sql"
    count(input.derived.sql_statements) > 0
    not unapproved_statement
}
