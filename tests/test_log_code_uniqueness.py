"""Log codes are what operators alert on, so one code must mean one thing.

`docs/error-codes.md` says a code is "a stable identifier for a situation, not a 1:1 alias for one
message", and that "a handful are reused across two related events". Both halves were wrong in a way
that mattered: the reuse was 96 codes, not a handful, and three of those pairings were not related
events at all — a security signal sharing a code with ordinary traffic:

  * `NRVQ-API-7080` covered `rate_limit.fail_open` (Redis unreachable, the HTTP throttle is letting
    everything through) alongside `cluster_info.served`. Alerting on the rate limiter failing open
    also fired on every console page view, so the alert had to be silenced to be usable — which is
    the same thing as not having it.
  * `NRVQ-API-7081` covered `rate_limit.exceeded` (a real 429) alongside `mitre.generate_batch`.
  * `NRVQ-API-7020` covered `policy.priority_band_denied` alongside two `.listed` reads.

Those three now have their own codes (7133/7134/7135). The remaining 96 are benign — `.loaded` beside
`.recovered`, and similar — and this module freezes them so the number can only go down.

The invariant with teeth is the FIRST test, not the ratchet: a code that carries a security signal
must not also carry routine traffic, whatever the total count does.
"""

from __future__ import annotations

import collections
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# `log.warning("nrvq.some.event", ..., code="NRVQ-API-7080")`, across line breaks.
_LOG = re.compile(
    r'log\.(?:debug|info|warning|error|critical)\(\s*\n?\s*"([a-z0-9_.]+)"'
    # The gap must not cross into the NEXT log call. Without that guard a call whose code carries a
    # suffix (`code="NRVQ-API-7081-ERR"`) fails to match locally, and the lazy quantifier runs on and
    # steals a later call's code — which silently attributed `coverage.mapping_missing` to 7081 and
    # made this module report a duplicate that did not exist.
    r'((?:(?!log\.)[\s\S])*?)code="(NRVQ-[A-Z]+-\d+(?:-[A-Z]+)*)"'
)

# An event whose whole purpose is to be alerted on.
_SECURITY = re.compile(
    r"fail_open|denied|blocked|refused|exceeded|violation|poison|quarantin|unreachable|degraded"
    r"|tamper|forged|escalat|revoked|expired|invalid|unauthor"
)
# An event that happens on ordinary, healthy traffic.
_ROUTINE = re.compile(
    r"\.(served|listed|loaded|computed|computed_all|generate_batch|list|open|warmed|created"
    r"|updated|deleted|ok|start|ready|seen)$"
)

# Frozen on 2026-08-20. Entries may be REMOVED as codes are split; adding one is a regression.
KNOWN_DUPLICATES: dict[str, tuple[str, ...]] = {
    "NRVQ-API-7018": ('nrvq.api.policy.deleted', 'nrvq.api.policy.view_sentinel_namespace'),
    "NRVQ-API-7019": ('nrvq.api.policy.overlay_audit_mode_refused', 'nrvq.api.policy.write_scope_denied'),
    "NRVQ-API-7020": ('nrvq.api.audit.listed', 'nrvq.api.deployments.listed'),
    "NRVQ-API-7033": ('nrvq.api.agent.registry_read_failed', 'nrvq.api.agent.trust_persist_failed', 'nrvq.api.agents.last_seen_failed'),
    "NRVQ-API-7035": ('nrvq.api.agent.overrides_warm_failed', 'nrvq.startup.agent_overrides_warm_failed'),
    "NRVQ-API-7040": ('nrvq.api.tools.list', 'nrvq.api.ws_audit.open'),
    "NRVQ-API-7050": ('nrvq.api.asset_graph.served', 'nrvq.api.body_too_large'),
    "NRVQ-API-7060": ('nrvq.attack_graph.computed', 'nrvq.attack_graph.computed_all'),
    "NRVQ-API-7063": ('nrvq.api.settings.mirror_failed', 'nrvq.api.settings.warmed', 'nrvq.startup.ns_settings_warm_failed'),
    "NRVQ-API-7080": ('nrvq.api.cluster_info.served', 'nrvq.api.mitre.generate_no_classes'),
    "NRVQ-API-7081": ('nrvq.api.coverage.served', 'nrvq.api.mitre.generate_batch'),
    "NRVQ-API-7081-ERR": ('nrvq.api.coverage.agent_class_efficacy_failed', 'nrvq.api.coverage.agent_class_query_failed', 'nrvq.api.coverage.mapping_missing'),
    "NRVQ-API-7084": ('nrvq.api.agent.series_truncated', 'nrvq.api.settings.served'),
    "NRVQ-API-7090": ('nrvq.api.apikey.authenticated', 'nrvq.api.system_health.degraded'),
    "NRVQ-API-7091": ('nrvq.api.keys.listed', 'nrvq.api.system_health.liveness_unavailable'),
    "NRVQ-API-7092": ('nrvq.api.keys.created', 'nrvq.api.redteam.audit_emit_failed', 'nrvq.api.system_health.liveness_failed'),
    "NRVQ-API-7093": ('nrvq.api.keys.revoked', 'nrvq.api.verb_overrides.warm_failed'),
    "NRVQ-API-7094": ('nrvq.api.packs.listed', 'nrvq.startup.verb_overrides_warm_failed'),
    "NRVQ-API-7097": ('nrvq.api.pack.error', 'nrvq.api.packs.manifest_missing'),
    "NRVQ-API-7098": ('nrvq.api.pack.override_reverted', 'nrvq.api.pack.override_saved'),
    "NRVQ-API-7099": ('nrvq.api.insecure_default_secret', 'nrvq.api.pack.weaken_applied'),
    "NRVQ-API-7100": ('nrvq.api.log_level_applied', 'nrvq.api.policies.effective'),
    "NRVQ-API-7102": ('nrvq.api.intent.coverage', 'nrvq.api.intent.coverage_eval_failed', 'nrvq.startup.audit_fanout_dropped'),
    "NRVQ-API-7103": ('nrvq.api.intent.draft_created', 'nrvq.audit_hub.peer_publish_skipped'),
    "NRVQ-API-7110": ('nrvq.api.baseline.compiled', 'nrvq.api.capability.defend', 'nrvq.api.intent.proposed', 'nrvq.api.retention.drafts_expired', 'nrvq.api.toolverb.promote'),
    "NRVQ-API-7111": ('nrvq.api.baseline.listed', 'nrvq.api.intent.dry_run', 'nrvq.api.retention.gc_failed', 'nrvq.api.toolverb.demote'),
    "NRVQ-API-7112": ('nrvq.api.baseline.updated', 'nrvq.api.graph.node_removed', 'nrvq.api.intent.draft_created', 'nrvq.api.retention.drafts_capped'),
    "NRVQ-API-7113": ('nrvq.api.policy_compliance.read', 'nrvq.api.retention.cap_failed', 'nrvq.api.threats.mcp_registry_unavailable'),
    "NRVQ-API-7114": ('nrvq.api.intent.draft_dismissed', 'nrvq.api.policy_compliance.controls_unavailable'),
    "NRVQ-API-7120": ('nrvq.api.policy.scope_cap_exceeded', 'nrvq.api.sidecar_expiry.observe_failed'),
    "NRVQ-API-7121": ('nrvq.api.agent.deregistered', 'nrvq.api.sidecar_expiry.read_failed'),
    "NRVQ-API-7122": ('nrvq.api.apikey.expired', 'nrvq.api.graph.node_prune_failed', 'nrvq.api.sidecar_expiry.unnameable_credential'),
    "NRVQ-AUD-6000": ('nrvq.audit.init', 'nrvq.engine.audit_decision'),
    "NRVQ-AUD-6009": ('nrvq.audit.param_keys_failed', 'nrvq.retention.started'),
    "NRVQ-AUTH-14012": ('nrvq.auth.change_password_denied', 'nrvq.auth.login_failed', 'nrvq.auth.login_locked'),
    "NRVQ-AUTH-14014": ('nrvq.auth.default_admin_password', 'nrvq.auth.default_admin_seed_conflict'),
    "NRVQ-AUTH-14020": ('nrvq.auth.change_password_revoke_failed', 'nrvq.auth.identity_unbound_denied'),
    "NRVQ-AUTH-14022": ('nrvq.auth.attested_namespace_conflicts_with_claim', 'nrvq.auth.identity_binding_partial'),
    "NRVQ-AUTH-14023": ('nrvq.auth.attested_namespace_denied', 'nrvq.auth.spiffe_namespace_mismatch'),
    "NRVQ-CLI-8004": ('nrvq.cli.bad_json', 'nrvq.cli.config_invalid', 'nrvq.cli.http_error', 'nrvq.cli.not_found', 'nrvq.cli.timeout'),
    "NRVQ-DB-9002": ('nrvq.db.closed', 'nrvq.db.default_partition_skipped'),
    "NRVQ-DB-9003": ('nrvq.db.partition_create_failed', 'nrvq.db.schema_compat_applied'),
    "NRVQ-DB-9023": ('nrvq.cache.analysis.hit', 'nrvq.cache.eval.hook_failed'),
    "NRVQ-DB-9024": ('nrvq.cache.agent_flags_failed', 'nrvq.cache.analysis.set'),
    "NRVQ-DB-9025": ('nrvq.cache.analysis.invalidated', 'nrvq.cache.eval_and_flags_failed'),
    "NRVQ-DB-9026": ('nrvq.cache.override_parse_failed', 'nrvq.cache.token.revoked'),
    "NRVQ-ENG-2049": ('nrvq.engine.trust.cache_failed', 'nrvq.engine.trust.cache_set_failed'),
    "NRVQ-ENG-2050": ('nrvq.attack_graph.compute_started', 'nrvq.engine.trust.freeze_check_failed'),
    "NRVQ-ENG-2051": ('nrvq.attack_graph.no_assets', 'nrvq.engine.agent_registry.write_failed'),
    "NRVQ-ENG-2052": ('nrvq.attack_graph.compute_completed', 'nrvq.opa.server_started'),
    "NRVQ-ENG-2053": ('nrvq.attack_graph.eval_failed', 'nrvq.opa.policy_pushed'),
    "NRVQ-ENG-2054": ('nrvq.opa.delete_failed', 'nrvq.opa.push_failed'),
    "NRVQ-ENG-2055": ('nrvq.engine.no_policy_loaded', 'nrvq.opa.capabilities_check_failed'),
    "NRVQ-ENG-2056": ('nrvq.engine.policy_load_pending', 'nrvq.eval.opa_recovered'),
    "NRVQ-ENG-2057": ('nrvq.engine.unattributed_block', 'nrvq.eval.opa_failed_persistent', 'nrvq.opa.module_missing'),
    "NRVQ-ENG-2060": ('nrvq.engine.policy_mode.audit_softened', 'nrvq.engine.trust.override_check_failed'),
    "NRVQ-ENG-2061": ('nrvq.engine.fail_closed_register_failed', 'nrvq.engine.posture.unreadable_on_failure_path', 'nrvq.engine.rate_limit.classify_failed', 'nrvq.engine.verb_overrides.refreshed'),
    "NRVQ-ENG-2063": ('nrvq.masking.url_redaction_failed', 'nrvq.opa.warm_failed'),
    "NRVQ-FLT-15000": ('nrvq.fleet.relay_pushed', 'nrvq.fleet.relay_started'),
    "NRVQ-FLT-15002": ('nrvq.fleet.heartbeat', 'nrvq.fleet.heartbeat_sent'),
    "NRVQ-FLT-15011": ('nrvq.fleet.db_connected', 'nrvq.fleet.started'),
    "NRVQ-FLT-15016": ('nrvq.fleet.pull_failed', 'nrvq.fleet.puller_no_trust_root', 'nrvq.fleet.puller_started'),
    "NRVQ-FLT-15018": ('nrvq.fleet.bundle_verify_failed', 'nrvq.fleet.bundle_wrong_cluster'),
    "NRVQ-FLT-15019": ('nrvq.fleet.bundle_expired', 'nrvq.fleet.bundle_not_yet_valid'),
    "NRVQ-FLT-15020": ('nrvq.fleet.rollout_report_failed', 'nrvq.fleet.rollout_reported'),
    "NRVQ-FLT-15022": ('nrvq.fleet.bundle_applied', 'nrvq.fleet.bundle_apply_failed'),
    "NRVQ-FLT-15025": ('nrvq.fleet.drilldown_failed', 'nrvq.fleet.drilldown_served'),
    "NRVQ-FLT-15034": ('nrvq.fleet.joined', 'nrvq.startup.join_state_load_failed'),
    "NRVQ-GRP-11016": ('nrvq.engine.graph.restore_failed', 'nrvq.graph.cache_miss'),
    "NRVQ-MCP-5046": ('nrvq.mcp.http.pin_store_degraded', 'nrvq.mcp.pins.control_plane_unreachable'),
    "NRVQ-MCP-5047": ('nrvq.mcp.http.pin_store_recovered', 'nrvq.mcp.pins.loaded_from_control_plane'),
    "NRVQ-MCP-5048": ('nrvq.mcp.pins.control_plane_recovered', 'nrvq.mcp.pins.report_failed'),
    "NRVQ-MCP-5063": ('nrvq.mcp.content_guard.budget_exhausted', 'nrvq.mcp.tool_header_denied'),
    "NRVQ-MCP-5067": ('nrvq.mcp.gate_a.item_list_flagged', 'nrvq.mcp.http.pin_store_degraded'),
    "NRVQ-MCP-5068": ('nrvq.mcp.gate_a.elicitation_flagged', 'nrvq.mcp.gate_a.server_blocked'),
    "NRVQ-MCP-5069": ('nrvq.mcp.notification_flagged', 'nrvq.mcp.server.decision'),
    "NRVQ-MCP-5071": ('nrvq.mcp.servers.control_plane_recovered', 'nrvq.mcp.servers.loaded'),
    "NRVQ-RED-13001": ('nrvq.redteam.attack_not_blocked', 'nrvq.redteam.rule_mismatch'),
    "NRVQ-RED-13009": ('nrvq.redteam.retention', 'nrvq.redteam.suite_lock_unavailable'),
    "NRVQ-REG-5011": ('nrvq.policy.eval_cache_cleared', 'nrvq.policy.reapplied'),
    "NRVQ-REG-5012": ('nrvq.policy.applied_to_target', 'nrvq.policy.reload_cache_miss'),
    "NRVQ-REG-5013": ('nrvq.policy.reloaded', 'nrvq.policy.versions_pruned'),
    "NRVQ-REG-5014": ('nrvq.policy.lazy_loaded', 'nrvq.policy.version_prune_failed'),
    "NRVQ-REG-5015": ('nrvq.policy.cache_warmed', 'nrvq.policy.namespaces_for_class_failed'),
    "NRVQ-REG-5016": ('nrvq.policy.remote_unloaded', 'nrvq.policy.versions_rehydrated'),
    "NRVQ-REG-5017": ('nrvq.policy.remote_reloaded', 'nrvq.policy.version_rehydrate_failed'),
    "NRVQ-SDC-3001": ('nrvq.sidecar.close_failed', 'nrvq.sidecar.connection_error'),
    "NRVQ-SDC-3003": ('nrvq.sidecar.audit_error', 'nrvq.sidecar.process_error'),
    "NRVQ-SDC-3012": ('nrvq.sidecar.call_depth_clamped', 'nrvq.sidecar.call_depth_malformed', 'nrvq.sidecar.call_depth_negative', 'nrvq.sidecar.http.process_error'),
    "NRVQ-SDC-3013": ('nrvq.sidecar.log_level_applied', 'nrvq.sidecar.readyz.opa_unreachable'),
    "NRVQ-SDC-3032": ('nrvq.sidecar.mode.proxy', 'nrvq.sidecar.remote_evaluator.fail_open', 'nrvq.sidecar.remote_evaluator.mtls_enabled'),
    "NRVQ-SDC-3033": ('nrvq.sidecar.mode.embedded', 'nrvq.sidecar.remote_evaluator.unexpected_error'),
    "NRVQ-SDK-1013": ('nrvq.sdk.evaluate.circuit_open', 'nrvq.sdk.fallback'),
    "NRVQ-SDK-1041": ('nrvq.langgraph.allowed', 'nrvq.langgraph.denied'),
    "NRVQ-SDK-1043": ('nrvq.langgraph.output_dlp_failed', 'nrvq.sdk.output_dlp_redacted'),
    "NRVQ-SIEM-14000": ('nrvq.siem.forwarded', 'nrvq.siem.started'),
}


def _codes_to_events() -> dict[str, set[str]]:
    found: dict[str, set[str]] = collections.defaultdict(set)
    for path in sorted((REPO / "norviq").rglob("*.py")):
        for match in _LOG.finditer(path.read_text()):
            found[match.group(3)].add(match.group(1))
    return dict(found)


def test_the_extractor_still_finds_log_codes():
    """A positive control. Without it, every assertion below passes when the regex stops matching.

    That is not hypothetical for this pattern: the emitters are hand-written across ~50 modules and a
    reformat that moves `code=` onto its own line, or a switch to a helper, silently empties the scan.
    An empty scan and a clean codebase produce identical green.
    """
    codes = _codes_to_events()
    assert len(codes) > 380, (
        f"only {len(codes)} log codes found in norviq/ — the extractor regex has stopped matching "
        f"the way codes are written, so every other assertion in this module is now vacuous. Fix "
        f"the regex before trusting a green run here."
    )
    assert "NRVQ-API-7133" in codes, (
        "the rate-limiter fail-open code is not being extracted; the scan is not reading what it "
        "thinks it is reading."
    )


def test_no_security_signal_shares_a_code_with_routine_traffic():
    """The invariant that actually protects an operator.

    Sharing a code between two quiet events is untidy. Sharing one between "the rate limiter is no
    longer enforcing" and "somebody opened the dashboard" makes the alert unusable, and an alert
    that has to be silenced is indistinguishable from one that was never wired up.
    """
    offenders = []
    for code, events in sorted(_codes_to_events().items()):
        security = sorted(e for e in events if _SECURITY.search(e))
        routine = sorted(e for e in events if _ROUTINE.search(e))
        if security and routine:
            offenders.append(f"{code}: {', '.join(security)}  <-shares code with->  {', '.join(routine)}")
    assert not offenders, (
        "a code carrying a security signal also fires on ordinary traffic, so alerting on it is "
        "not possible without alerting on everything. Give the security event its own code and "
        "document it in docs/error-codes.md:\n  " + "\n  ".join(offenders)
    )


def test_duplicate_log_codes_only_ever_decrease():
    """A ratchet over the benign remainder: split them when convenient, never add one."""
    current = {c: tuple(sorted(v)) for c, v in _codes_to_events().items() if len(v) > 1}

    added = sorted(set(current) - set(KNOWN_DUPLICATES))
    assert not added, (
        "these codes now cover more than one event. Pick a fresh number for the new event and add a "
        "row to docs/error-codes.md — operators grep the code, so a second meaning on an existing "
        "one silently changes what their alert matches:\n  "
        + "\n  ".join(f"{c}: {', '.join(current[c])}" for c in added)
    )

    fixed = sorted(set(KNOWN_DUPLICATES) - set(current))
    assert not fixed, (
        "these codes are no longer duplicated — good. Delete them from KNOWN_DUPLICATES so the "
        "ratchet holds the improvement, otherwise the list stops describing the codebase and the "
        "next real duplicate hides behind a stale entry:\n  " + "\n  ".join(fixed)
    )
