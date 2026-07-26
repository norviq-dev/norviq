package norviq.custom

# INTENT POLICY — "this agent may READ from the vector store, nothing else."
#
# Gates on what the call DOES (input.derived.verb), not on what the tool is CALLED. A tool-name
# allowlist is brittle in the dangerous direction here: under deny-by-default a missed alias
# (milvus_hybrid_search, milvus_get) does not leak — it locks out legitimate traffic, and that is what
# gets a policy switched off in week one.
#
# Verbs: read | write | delete | send | unknown
#
#   milvus_search / milvus_query        -> read
#   milvus_insert / qdrant_upsert       -> write
#   milvus_delete / milvus_drop_collection -> delete
#   send_email / post_webhook           -> send
#
# Scope it to one system by tool-name prefix — that is an explicit, honest check, unlike a guessed
# "source" field.
#
# ┌─ SCOPE IS NOT A PERIMETER ────────────────────────────────────────────────────────────────────┐
# │ This policy governs tools matching `scoped_source` and lets EVERYTHING ELSE fall through to    │
# │ the platform baseline. That is deliberate — a Milvus policy must not govern unrelated tools —  │
# │ but it means a tool named OUTSIDE the prefix escapes both gates here:                          │
# │                                                                                                │
# │     milvus_zzz_obscure  -> escalate   (in scope, unclassified, handled)                        │
# │     zzz_exfil           -> allow      (out of scope: NOT governed by this policy)              │
# │                                                                                                │
# │ Tool-name classification can never be a security boundary: the name is chosen by the agent     │
# │ side, so any lexicon can be routed around by renaming. Use this template to express INTENT     │
# │ within a system you already govern — not to keep unknown tools out.                            │
# │                                                                                                │
# │ For the perimeter, pair it with a deny-by-default TOOL ALLOWLIST for the class (see            │
# │ tool-allowlist-perimeter.rego): registration-based, so a novel name fails the list instead of  │
# │ bypassing it.                                                                                  │
# └────────────────────────────────────────────────────────────────────────────────────────────────┘

default decision = "block"
default rule_id = "read_only_intent"
default reason = "this agent class is permitted read operations only"

# Which system this policy governs. Widen or remove as needed.
scoped_source {
    startswith(lower(input.tool_name), "milvus_")
}

# Out of scope -> fall through to the platform baseline rather than being swept up by the default deny.
decision = "allow" {
    not scoped_source
}

# The intent: reads are permitted.
decision = "allow" {
    scoped_source
    input.derived.verb == "read"
}

# UNCLASSIFIED TOOLS.
#
# `unknown` means the classifier did not recognise the tool name — a new vendor tool, an internal
# wrapper, or a deliberately obscured name. It is a first-class value precisely so this policy can
# state what happens rather than leaving it implicit.
#
# Escalate (human review) is the recommended handling: neither silently denied, which strands
# legitimate new tools, nor silently permitted.
#
# SECURITY — do NOT change this to "allow". Classification keys on the tool NAME, which the agent side
# controls, so `allow { verb == "unknown" }` is a universal bypass: anything named unrecognisably is
# permitted. If you must allow a specific unclassified tool, name it explicitly instead:
#
#     decision = "allow" { input.tool_name == "milvus_hybrid_search_v2" }
#
decision = "escalate" {
    scoped_source
    input.derived.verb == "unknown"
}
rule_id = "read_only_intent_unclassified" {
    scoped_source
    input.derived.verb == "unknown"
}
reason = "unclassified tool on a read-only source — needs human review" {
    scoped_source
    input.derived.verb == "unknown"
}
