"""Log codes are what operators alert on, so one code must not mean two different things.

`docs/error-codes.md` deliberately reuses a code across events that are "one situation" — `.loaded`
beside `.recovered`, the same failure at two call sites. That is fine and this module does not fight
it. What is not fine is a code that fires BOTH on something you would page on and on ordinary healthy
traffic: the alert has to be silenced to be usable, and a silenced alert is the same as an absent one.

Five of those shipped. The worst was `NRVQ-SDC-3032`, which carried two startup INFO lines
(`mode.proxy`, `mtls_enabled`) and also `remote_evaluator.fail_open` — the line emitted when the
sidecar lets a tool call through UNJUDGED because the control plane is unreachable. The reference row
described it as "Two events, both about proxy mode" and never mentioned the third, so an operator who
read the docs correctly and filtered 3032 as startup noise was filtering away the only signal that
says agents are currently ungoverned. Also split out: `settings.mirror_failed` and
`ns_settings_warm_failed` (saved posture is not the posture being enforced) from `settings.warmed`;
`body_too_large` from `asset_graph.served`; `trust.freeze_check_failed` from
`attack_graph.compute_started`; `pull_failed`/`puller_no_trust_root` from `puller_started`.

**Severity is taken from the log level, not from the words in the event name.** An earlier version of
this module keyword-matched both halves — a "security" list and a "routine" list — and reported zero
problems while all five above were live: `body_too_large` contains no security word and `mode.proxy`
contains no routine word, so neither pairing matched. The level is written at every call site, is
derived from the code rather than hand-maintained, and covers the next module the day it is added.

Known gap, stated rather than papered over: two events logged at the SAME level, one alertable and one
not, are invisible here. That is rarer, because routine events are not logged at warning.
"""

from __future__ import annotations

import collections
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# `log.warning("nrvq.some.event", ..., code="NRVQ-API-7080")`, across line breaks.
_LOG = re.compile(
    r'log\.(?P<level>debug|info|warning|error|critical)\(\s*\n?\s*"(?P<event>[a-z0-9_.]+)"'
    # The gap must not cross into the NEXT log call. Without that guard a call whose code carries a
    # suffix (`code="NRVQ-API-7081-ERR"`) fails to match locally, the lazy quantifier runs on and
    # steals a later call's code, and this module invents duplicates that do not exist.
    # Named groups on purpose: this regex previously used positional ones, and adding the level
    # capture silently shifted `code` from group 3 to group 4, so the scan keyed on the GAP text.
    r'(?:(?!log\.)[\s\S])*?code="(?P<code>NRVQ-[A-Z]+-\d+(?:-[A-Z]+)*)"'
)

_ALERTABLE = {"warning", "error", "critical"}
_ROUTINE = {"debug", "info"}

# Codes that still mix an alertable level with a routine one. Frozen 2026-08-20 at 40. Every one was
# reviewed and none is a security signal hiding behind routine traffic — they are mostly a debug
# trace beside a warning in the same module. Entries may be REMOVED as codes are split; adding one
# is a regression.
MIXED_LEVELS: dict[str, tuple[str, ...]] = {
    "NRVQ-API-7018": ('nrvq.api.policy.deleted', 'nrvq.api.policy.view_sentinel_namespace'),
    "NRVQ-API-7084": ('nrvq.api.agent.series_truncated', 'nrvq.api.settings.served'),
    "NRVQ-API-7090": ('nrvq.api.apikey.authenticated', 'nrvq.api.system_health.degraded'),
    "NRVQ-API-7091": ('nrvq.api.keys.listed', 'nrvq.api.system_health.liveness_unavailable'),
    "NRVQ-API-7092": ('nrvq.api.keys.created', 'nrvq.api.redteam.audit_emit_failed', 'nrvq.api.system_health.liveness_failed'),
    "NRVQ-API-7093": ('nrvq.api.keys.revoked', 'nrvq.api.verb_overrides.warm_failed'),
    "NRVQ-API-7094": ('nrvq.api.packs.listed', 'nrvq.startup.verb_overrides_warm_failed'),
    "NRVQ-API-7102": ('nrvq.api.intent.coverage', 'nrvq.api.intent.coverage_eval_failed', 'nrvq.startup.audit_fanout_dropped'),
    "NRVQ-API-7111": ('nrvq.api.baseline.listed', 'nrvq.api.intent.dry_run', 'nrvq.api.retention.gc_failed', 'nrvq.api.toolverb.demote'),
    "NRVQ-API-7113": ('nrvq.api.policy_compliance.read', 'nrvq.api.retention.cap_failed', 'nrvq.api.threats.mcp_registry_unavailable'),
    "NRVQ-API-7114": ('nrvq.api.intent.draft_dismissed', 'nrvq.api.policy_compliance.controls_unavailable'),
    "NRVQ-API-7120": ('nrvq.api.policy.scope_cap_exceeded', 'nrvq.api.sidecar_expiry.observe_failed'),
    "NRVQ-API-7121": ('nrvq.api.agent.deregistered', 'nrvq.api.sidecar_expiry.read_failed'),
    "NRVQ-API-7122": ('nrvq.api.apikey.expired', 'nrvq.api.graph.node_prune_failed', 'nrvq.api.sidecar_expiry.unnameable_credential'),
    "NRVQ-AUD-6009": ('nrvq.audit.param_keys_failed', 'nrvq.retention.started'),
    "NRVQ-AUTH-14014": ('nrvq.auth.default_admin_password', 'nrvq.auth.default_admin_seed_conflict'),
    "NRVQ-DB-9002": ('nrvq.db.closed', 'nrvq.db.default_partition_skipped'),
    "NRVQ-DB-9003": ('nrvq.db.partition_create_failed', 'nrvq.db.schema_compat_applied'),
    "NRVQ-DB-9023": ('nrvq.cache.analysis.hit', 'nrvq.cache.eval.hook_failed'),
    "NRVQ-DB-9024": ('nrvq.cache.agent_flags_failed', 'nrvq.cache.analysis.set'),
    "NRVQ-DB-9025": ('nrvq.cache.analysis.invalidated', 'nrvq.cache.eval_and_flags_failed'),
    "NRVQ-DB-9026": ('nrvq.cache.override_parse_failed', 'nrvq.cache.token.revoked'),
    "NRVQ-ENG-2051": ('nrvq.attack_graph.no_assets', 'nrvq.engine.agent_registry.write_failed'),
    "NRVQ-ENG-2053": ('nrvq.attack_graph.eval_failed', 'nrvq.opa.policy_pushed'),
    "NRVQ-ENG-2056": ('nrvq.engine.policy_load_pending', 'nrvq.eval.opa_recovered'),
    "NRVQ-ENG-2060": ('nrvq.engine.policy_mode.audit_softened', 'nrvq.engine.trust.override_check_failed'),
    "NRVQ-ENG-2061": ('nrvq.engine.fail_closed_register_failed', 'nrvq.engine.posture.unreadable_on_failure_path', 'nrvq.engine.rate_limit.classify_failed', 'nrvq.engine.verb_overrides.refreshed'),
    "NRVQ-FLT-15022": ('nrvq.fleet.bundle_applied', 'nrvq.fleet.bundle_apply_failed'),
    "NRVQ-FLT-15025": ('nrvq.fleet.drilldown_failed', 'nrvq.fleet.drilldown_served'),
    "NRVQ-FLT-15034": ('nrvq.fleet.joined', 'nrvq.startup.join_state_load_failed'),
    "NRVQ-GRP-11016": ('nrvq.engine.graph.restore_failed', 'nrvq.graph.cache_miss'),
    "NRVQ-MCP-5048": ('nrvq.mcp.pins.control_plane_recovered', 'nrvq.mcp.pins.report_failed'),
    "NRVQ-RED-13009": ('nrvq.redteam.retention', 'nrvq.redteam.suite_lock_unavailable'),
    "NRVQ-REG-5014": ('nrvq.policy.lazy_loaded', 'nrvq.policy.version_prune_failed'),
    "NRVQ-REG-5015": ('nrvq.policy.cache_warmed', 'nrvq.policy.namespaces_for_class_failed'),
    "NRVQ-REG-5017": ('nrvq.policy.remote_reloaded', 'nrvq.policy.version_rehydrate_failed'),
    "NRVQ-SDC-3001": ('nrvq.sidecar.close_failed', 'nrvq.sidecar.connection_error'),
    "NRVQ-SDC-3013": ('nrvq.sidecar.log_level_applied', 'nrvq.sidecar.readyz.opa_unreachable'),
    "NRVQ-SDC-3033": ('nrvq.sidecar.mode.embedded', 'nrvq.sidecar.remote_evaluator.unexpected_error'),
    "NRVQ-SDK-1041": ('nrvq.langgraph.allowed', 'nrvq.langgraph.denied'),
}

# Codes covering more than one event at the same severity. Untidy when reading logs, harmless when
# alerting. Frozen so the number can only fall.
KNOWN_DUPLICATES: dict[str, tuple[str, ...]] = {
    "NRVQ-API-7019": ('nrvq.api.policy.overlay_audit_mode_refused', 'nrvq.api.policy.write_scope_denied'),
    "NRVQ-API-7020": ('nrvq.api.audit.listed', 'nrvq.api.deployments.listed'),
    "NRVQ-API-7033": ('nrvq.api.agent.registry_read_failed', 'nrvq.api.agent.trust_persist_failed', 'nrvq.api.agents.last_seen_failed'),
    "NRVQ-API-7035": ('nrvq.api.agent.overrides_warm_failed', 'nrvq.startup.agent_overrides_warm_failed'),
    "NRVQ-API-7040": ('nrvq.api.tools.list', 'nrvq.api.ws_audit.open'),
    "NRVQ-API-7060": ('nrvq.attack_graph.computed', 'nrvq.attack_graph.computed_all'),
    "NRVQ-API-7080": ('nrvq.api.cluster_info.served', 'nrvq.api.mitre.generate_no_classes'),
    "NRVQ-API-7081": ('nrvq.api.coverage.served', 'nrvq.api.mitre.generate_batch'),
    "NRVQ-API-7081-ERR": ('nrvq.api.coverage.agent_class_efficacy_failed', 'nrvq.api.coverage.agent_class_query_failed', 'nrvq.api.coverage.mapping_missing'),
    "NRVQ-API-7097": ('nrvq.api.pack.error', 'nrvq.api.packs.manifest_missing'),
    "NRVQ-API-7098": ('nrvq.api.pack.override_reverted', 'nrvq.api.pack.override_saved'),
    "NRVQ-API-7099": ('nrvq.api.insecure_default_secret', 'nrvq.api.pack.weaken_applied'),
    "NRVQ-API-7100": ('nrvq.api.log_level_applied', 'nrvq.api.policies.effective'),
    "NRVQ-API-7103": ('nrvq.api.intent.draft_created', 'nrvq.audit_hub.peer_publish_skipped'),
    "NRVQ-API-7110": ('nrvq.api.baseline.compiled', 'nrvq.api.capability.defend', 'nrvq.api.intent.proposed', 'nrvq.api.retention.drafts_expired', 'nrvq.api.toolverb.promote'),
    "NRVQ-API-7112": ('nrvq.api.baseline.updated', 'nrvq.api.graph.node_removed', 'nrvq.api.intent.draft_created', 'nrvq.api.retention.drafts_capped'),
    "NRVQ-AUD-6000": ('nrvq.audit.init', 'nrvq.engine.audit_decision'),
    "NRVQ-AUTH-14012": ('nrvq.auth.change_password_denied', 'nrvq.auth.login_failed', 'nrvq.auth.login_locked'),
    "NRVQ-AUTH-14020": ('nrvq.auth.change_password_revoke_failed', 'nrvq.auth.identity_unbound_denied'),
    "NRVQ-AUTH-14022": ('nrvq.auth.attested_namespace_conflicts_with_claim', 'nrvq.auth.identity_binding_partial'),
    "NRVQ-AUTH-14023": ('nrvq.auth.attested_namespace_denied', 'nrvq.auth.spiffe_namespace_mismatch'),
    "NRVQ-CLI-8004": ('nrvq.cli.bad_json', 'nrvq.cli.config_invalid', 'nrvq.cli.http_error', 'nrvq.cli.not_found', 'nrvq.cli.timeout'),
    "NRVQ-ENG-2049": ('nrvq.engine.trust.cache_failed', 'nrvq.engine.trust.cache_set_failed'),
    "NRVQ-ENG-2052": ('nrvq.attack_graph.compute_completed', 'nrvq.opa.server_started'),
    "NRVQ-ENG-2054": ('nrvq.opa.delete_failed', 'nrvq.opa.push_failed'),
    "NRVQ-ENG-2055": ('nrvq.engine.no_policy_loaded', 'nrvq.opa.capabilities_check_failed'),
    "NRVQ-ENG-2057": ('nrvq.engine.unattributed_block', 'nrvq.eval.opa_failed_persistent', 'nrvq.opa.module_missing'),
    "NRVQ-ENG-2063": ('nrvq.masking.url_redaction_failed', 'nrvq.opa.warm_failed'),
    "NRVQ-FLT-15000": ('nrvq.fleet.relay_pushed', 'nrvq.fleet.relay_started'),
    "NRVQ-FLT-15002": ('nrvq.fleet.heartbeat', 'nrvq.fleet.heartbeat_sent'),
    "NRVQ-FLT-15011": ('nrvq.fleet.db_connected', 'nrvq.fleet.started'),
    "NRVQ-FLT-15018": ('nrvq.fleet.bundle_verify_failed', 'nrvq.fleet.bundle_wrong_cluster'),
    "NRVQ-FLT-15019": ('nrvq.fleet.bundle_expired', 'nrvq.fleet.bundle_not_yet_valid'),
    "NRVQ-FLT-15020": ('nrvq.fleet.rollout_report_failed', 'nrvq.fleet.rollout_reported'),
    "NRVQ-MCP-5046": ('nrvq.mcp.http.pin_store_degraded', 'nrvq.mcp.pins.control_plane_unreachable'),
    "NRVQ-MCP-5047": ('nrvq.mcp.http.pin_store_recovered', 'nrvq.mcp.pins.loaded_from_control_plane'),
    "NRVQ-MCP-5063": ('nrvq.mcp.content_guard.budget_exhausted', 'nrvq.mcp.tool_header_denied'),
    "NRVQ-MCP-5067": ('nrvq.mcp.gate_a.item_list_flagged', 'nrvq.mcp.http.pin_store_degraded'),
    "NRVQ-MCP-5068": ('nrvq.mcp.gate_a.elicitation_flagged', 'nrvq.mcp.gate_a.server_blocked'),
    "NRVQ-MCP-5069": ('nrvq.mcp.notification_flagged', 'nrvq.mcp.server.decision'),
    "NRVQ-MCP-5071": ('nrvq.mcp.servers.control_plane_recovered', 'nrvq.mcp.servers.loaded'),
    "NRVQ-RED-13001": ('nrvq.redteam.attack_not_blocked', 'nrvq.redteam.rule_mismatch'),
    "NRVQ-REG-5011": ('nrvq.policy.eval_cache_cleared', 'nrvq.policy.reapplied'),
    "NRVQ-REG-5012": ('nrvq.policy.applied_to_target', 'nrvq.policy.reload_cache_miss'),
    "NRVQ-REG-5013": ('nrvq.policy.reloaded', 'nrvq.policy.versions_pruned'),
    "NRVQ-REG-5016": ('nrvq.policy.remote_unloaded', 'nrvq.policy.versions_rehydrated'),
    "NRVQ-SDC-3003": ('nrvq.sidecar.audit_error', 'nrvq.sidecar.process_error'),
    "NRVQ-SDC-3012": ('nrvq.sidecar.call_depth_clamped', 'nrvq.sidecar.call_depth_malformed', 'nrvq.sidecar.call_depth_negative', 'nrvq.sidecar.http.process_error'),
    "NRVQ-SDC-3032": ('nrvq.sidecar.mode.proxy', 'nrvq.sidecar.remote_evaluator.mtls_enabled'),
    "NRVQ-SDK-1013": ('nrvq.sdk.evaluate.circuit_open', 'nrvq.sdk.fallback'),
    "NRVQ-SDK-1043": ('nrvq.langgraph.output_dlp_failed', 'nrvq.sdk.output_dlp_redacted'),
    "NRVQ-SIEM-14000": ('nrvq.siem.forwarded', 'nrvq.siem.started'),
}


def _scan() -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    levels: dict[str, set[str]] = collections.defaultdict(set)
    events: dict[str, set[str]] = collections.defaultdict(set)
    for path in sorted((REPO / "norviq").rglob("*.py")):
        for match in _LOG.finditer(path.read_text()):
            levels[match["code"]].add(match["level"])
            events[match["code"]].add(match["event"])
    return dict(levels), dict(events)


def test_the_extractor_still_finds_log_codes():
    """A positive control. Without it, every assertion below passes when the regex stops matching.

    Not hypothetical: the emitters are hand-written across ~50 modules, and a reformat that moves
    `code=` onto its own line, or a switch to a helper, silently empties the scan. An empty scan and
    a clean codebase produce identical green.
    """
    levels, events = _scan()
    assert len(events) > 390, (
        f"only {len(events)} log codes found in norviq/ — the extractor regex has stopped matching "
        f"the way codes are written, so every other assertion in this module is now vacuous. Fix "
        f"the regex before trusting a green run here."
    )
    assert events.get("NRVQ-SDC-3036") == {"nrvq.sidecar.remote_evaluator.fail_open"}, (
        "the sidecar fail-open code is not being extracted as its own event; the scan is not "
        "reading what it thinks it is reading."
    )
    assert levels.get("NRVQ-SDC-3036") == {"warning"}, "log level is no longer being captured"


def test_no_alertable_event_shares_a_code_with_routine_traffic():
    """The invariant with teeth: severity taken from the level, which nobody has to maintain."""
    levels, events = _scan()
    offenders = []
    for code in sorted(levels):
        loud = sorted(levels[code] & _ALERTABLE)
        quiet = sorted(levels[code] & _ROUTINE)
        if loud and quiet and code not in MIXED_LEVELS:
            offenders.append(
                f"{code}: logged at {'/'.join(loud)} AND {'/'.join(quiet)} — "
                f"{', '.join(sorted(events[code]))}"
            )
    assert not offenders, (
        "a code fires both on something an operator would alert on and on ordinary traffic, so the "
        "alert must be silenced to be usable — which is the same as not having it. Give the "
        "alertable event its own code and document it in docs/error-codes.md:\n  "
        + "\n  ".join(offenders)
    )


def test_the_frozen_lists_do_not_go_stale():
    """Both baselines ratchet: a fixed entry must be deleted, or it hides the next real one."""
    levels, events = _scan()
    still_mixed = {c for c in levels if levels[c] & _ALERTABLE and levels[c] & _ROUTINE}
    fixed = sorted(set(MIXED_LEVELS) - still_mixed)
    assert not fixed, (
        "these codes no longer mix alertable and routine levels — good. Delete them from "
        "MIXED_LEVELS so the improvement is held:\n  " + "\n  ".join(fixed)
    )

    current = {c: tuple(sorted(v)) for c, v in events.items() if len(v) > 1}
    added = sorted(set(current) - set(KNOWN_DUPLICATES) - set(MIXED_LEVELS))
    assert not added, (
        "these codes now cover more than one event. Pick a fresh number and add a row to "
        "docs/error-codes.md — operators grep the code, so a second meaning silently changes what "
        "their alert matches:\n  "
        + "\n  ".join(f"{c}: {', '.join(current[c])}" for c in added)
    )
    gone = sorted(set(KNOWN_DUPLICATES) - set(current))
    assert not gone, (
        "these codes are no longer duplicated. Delete them from KNOWN_DUPLICATES:\n  "
        + "\n  ".join(gone)
    )
