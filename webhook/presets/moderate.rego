package norviq.presets.moderate

# Decision/rule_id/reason are resolved from PARTIAL-SET triggers (blocks/escalates) + a deterministic
# resolver — the same pattern the strict preset uses — so that when an input matches BOTH triggers
# (e.g. execute_sql carrying "drop") there is NO complete-rule conflict (F-12): exactly one decision
# binds. Precedence: block > escalate > allow; ties resolved by sorted rule_id (deterministic).

default decision = "allow"
default rule_id = "moderate_default_allow"
default reason = "Moderate preset allowed request"

# --- partial-set triggers (rule_id -> guard) ---
blocks["moderate_drop_block"] {
  contains(lower(input.tool_params.query), "drop")
}

escalates["moderate_escalate"] {
  input.tool_name == "execute_sql"
}

reasons = {
  "moderate_drop_block": "Moderate preset blocked destructive SQL",
  "moderate_escalate": "Moderate preset escalated high-risk request",
  "moderate_default_allow": "Moderate preset allowed request",
}

# --- resolver: block > escalate > allow; deterministic sorted rule_id; reason from the map ---
block_fired { blocks[_] }
escalate_fired { escalates[_] }

decision = "block" { block_fired }
decision = "escalate" { escalate_fired; not block_fired }

rule_id = sort([id | blocks[id]])[0] { block_fired }
rule_id = sort([id | escalates[id]])[0] { escalate_fired; not block_fired }

reason = reasons[rule_id]
