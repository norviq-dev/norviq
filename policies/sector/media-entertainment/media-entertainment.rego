# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Sector starter pack: MEDIA / ENTERTAINMENT.
# Flagship risk: leak of pre-release/embargoed content, DRM/key exfil, unauthorized distribution, or
# bulk subscriber/viewing-history exfil.
#   - pre-release / embargoed content access or export -> BLOCK    (media_prerelease_blocked)
#   - DRM / content-key access                          -> BLOCK    (media_drm_key_access_blocked)
#   - publish / distribute / takedown-bypass            -> ESCALATE (media_distribute_escalate)
#   - royalty / licensing financial action              -> ESCALATE (media_royalty_action_escalate)
#   - bulk subscriber PII / viewing-history export      -> BLOCK    (media_bulk_pii_export_blocked)
# Composes canonical PII (requires: pii). STARTER — tune verbs/thresholds. v0 (--v0-compatible).
package norviq.sector.media_entertainment

# >>> PACK-CONTRIB-BEGIN media-entertainment
media_tool = lower(input.tool_name)
media_prerelease_terms = ["prerelease", "pre_release", "embargo", "unreleased", "screener"]
media_access_verbs = ["access", "export", "download", "get", "fetch", "stream"]
media_drm_terms = ["drm", "decryption_key", "content_key", "license_key", "master_key", "get_key", "watermark_key"]
media_distribute_verbs = ["publish", "distribute", "release_content", "bypass_takedown", "override_takedown", "push_live"]
media_royalty_verbs = ["pay_royalty", "royalty_run", "licensing_payment", "license_fee", "settle_royalties"]
media_export_verbs = ["export", "download", "extract", "bulk_export"]
media_bulk_threshold = 100

media_is_access {
    contains(media_tool, media_access_verbs[_])
}

blocks["media_prerelease_blocked"] {
    contains(media_tool, media_prerelease_terms[_])
}
blocks["media_prerelease_blocked"] {
    media_is_access
    s := lower(sprintf("%v", [input.tool_params.content_status]))
    contains(s, "embargo")
}
blocks["media_prerelease_blocked"] {
    media_is_access
    s := lower(sprintf("%v", [input.tool_params.content_status]))
    contains(s, "prerelease")
}
reasons["media_prerelease_blocked"] = "Media: pre-release / embargoed content access blocked"

blocks["media_drm_key_access_blocked"] {
    contains(media_tool, media_drm_terms[_])
}
reasons["media_drm_key_access_blocked"] = "Media: DRM / content-key access blocked"

escalates["media_distribute_escalate"] {
    contains(media_tool, media_distribute_verbs[_])
}
reasons["media_distribute_escalate"] = "Media: publish / distribute / takedown change requires approval"

escalates["media_royalty_action_escalate"] {
    contains(media_tool, media_royalty_verbs[_])
}
reasons["media_royalty_action_escalate"] = "Media: royalty / licensing financial action requires approval"

blocks["media_bulk_pii_export_blocked"] {
    contains(media_tool, media_export_verbs[_])
    to_number(input.tool_params.count) > media_bulk_threshold
}
reasons["media_bulk_pii_export_blocked"] = "Media: bulk subscriber PII / viewing-history export over threshold blocked"
# >>> PACK-CONTRIB-END media-entertainment

# >>> RESOLVER-BEGIN
default decision = "allow"
default rule_id = "default_allow"
default reason = "Allowed"

blocks["__never__"] { false }
escalates["__never__"] { false }
audits["__never__"] { false }
reasons["__never__"] = "" { false }

block_fired { blocks[_] }
escalate_fired { escalates[_] }
audit_fired { audits[_] }

decision = "block" { block_fired }
decision = "escalate" { escalate_fired; not block_fired }
decision = "audit" { audit_fired; not block_fired; not escalate_fired }

rule_id = sort([id | blocks[id]])[0] { block_fired }
rule_id = sort([id | escalates[id]])[0] { escalate_fired; not block_fired }
rule_id = sort([id | audits[id]])[0] { audit_fired; not block_fired; not escalate_fired }

reason = reasons[sort([id | blocks[id]])[0]] { block_fired }
reason = reasons[sort([id | escalates[id]])[0]] { escalate_fired; not block_fired }
reason = reasons[sort([id | audits[id]])[0]] { audit_fired; not block_fired; not escalate_fired }
# >>> RESOLVER-END
