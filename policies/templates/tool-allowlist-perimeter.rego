package norviq.custom

# PERIMETER — "this agent class may call exactly these tools; everything else is denied."
#
# This is the policy that actually holds against an unrecognised tool name. It is REGISTRATION-based:
# a tool is permitted because a human put it on this list, not because a classifier recognised it. A
# novel or deliberately obscured name (`zzz_exfil`, `x1`, `do_thing`) fails the list rather than
# slipping past a lexicon.
#
# Contrast with a verb/intent policy (read-only-intent-deny-by-default.rego), which gates on WHAT a
# call does. That is the right tool for expressing intent INSIDE a system you already govern, but it
# cannot be a perimeter — tool names are chosen by the agent side, so any name-derived classification
# can be routed around by renaming. Use both: this file decides WHICH tools may be called, the intent
# policy decides WHAT they may do.
#
# ── HOW TO FILL THIS IN ────────────────────────────────────────────────────────────────────────────
# Do NOT author this list from memory. Run the class in Monitor mode first, let the console show the
# tools the agent actually calls, then promote the legitimate ones here. Before switching the class to
# enforcing, use Dry-Run to confirm the would-block list is empty — a non-empty list means the
# allowlist is not finished, and enforcing now would break real traffic.
#
# Every entry is a security decision. Keep the list short, and remove tools that stop being used —
# a dormant grant is a standing capability nobody is watching.

default decision = "block"
default rule_id = "tool_allowlist_perimeter"
default reason = "tool is not on this agent class's approved list"

# ── THE ALLOWLIST ──────────────────────────────────────────────────────────────────────────────────
allowed_tools = {
    "search_kb",
    "get_order",
    "get_customer",
    "milvus_search",
    "milvus_query",
}

decision = "allow" {
    allowed_tools[input.tool_name]
}

# ── UNLISTED TOOLS ─────────────────────────────────────────────────────────────────────────────────
#
# Everything not on the list hits the `default decision = "block"` above. That is the point, and it is
# what makes an unrecognisable name a non-event: it is denied for not being listed, no classification
# required.
#
# `input.derived.verb` is still worth recording here, because it tells the REVIEWER what the denied
# call was trying to do — read, write, delete, send, or unknown. `unknown` on a denied call is the
# signal worth alerting on: it means someone invoked a tool whose purpose the classifier could not
# determine, which is exactly what probing with novel names looks like.
reason = "unlisted tool attempted a delete — review this agent's behaviour" {
    not allowed_tools[input.tool_name]
    input.derived.verb == "delete"
}
reason = "unlisted AND unclassified tool — the call's purpose could not be determined" {
    not allowed_tools[input.tool_name]
    input.derived.verb == "unknown"
}
rule_id = "tool_allowlist_perimeter_unclassified" {
    not allowed_tools[input.tool_name]
    input.derived.verb == "unknown"
}
