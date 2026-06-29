# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.sector.media_entertainment_test

import data.norviq.sector.media_entertainment as media

test_prerelease_name_blocked {
    media.decision == "block" with input as {"tool_name": "export_prerelease_cut", "tool_params": {}}
    media.rule_id == "media_prerelease_blocked" with input as {"tool_name": "export_prerelease_cut", "tool_params": {}}
}

test_embargoed_status_export_blocked {
    media.decision == "block" with input as {"tool_name": "export_asset", "tool_params": {"content_status": "EMBARGOED"}}
}

test_drm_key_access_blocked {
    media.decision == "block" with input as {"tool_name": "get_content_key", "tool_params": {}}
}

test_distribute_escalates {
    media.decision == "escalate" with input as {"tool_name": "publish_title", "tool_params": {}}
    media.rule_id == "media_distribute_escalate" with input as {"tool_name": "publish_title", "tool_params": {}}
}

test_royalty_escalates {
    media.decision == "escalate" with input as {"tool_name": "royalty_run", "tool_params": {}}
}

test_bulk_export_blocked {
    media.decision == "block" with input as {"tool_name": "bulk_export", "tool_params": {"count": 9000}}
}

test_benign_stream_allowed {
    media.decision == "allow" with input as {"tool_name": "get_catalog", "tool_params": {"genre": "drama"}}
}
