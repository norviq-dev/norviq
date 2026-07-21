# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Source capability registry — the verb-surface model + defended/undefended/dormant classifier."""

import pytest

from norviq.engine.capability import (
    CapabilityStatus,
    SourceClass,
    Verb,
    classify_source,
    defense_meta,
    mutating_verbs_of,
    source_type_of,
    worst_open_verb,
)
from norviq.engine.capability.source_registry import source_meta, verb_of_tool, verb_risk
from norviq.engine.graph.models import RiskLevel


class TestSourceTypeResolution:
    @pytest.mark.parametrize(
        "uri,expected",
        [
            ("postgresql/users", "postgresql"),
            ("elasticsearch/knowledge_base", "elasticsearch"),
            ("es://kb", "elasticsearch"),      # scheme form + alias
            ("postgres/orders", "postgresql"), # alias
            ("smtp/outbound", "smtp"),
            ("s3/bucket", "s3"),
            ("gcs/blob", "s3"),                # alias → object-store
            ("mysql/x", ""),                   # unknown source type
            ("", ""),
        ],
    )
    def test_source_type_of(self, uri, expected):
        assert source_type_of(uri) == expected

    def test_source_class_is_modelled_for_all_waves(self):
        # decision (c): egress + object-store are first-class from day 1, not just datastores.
        assert source_meta("elasticsearch")["source_class"] == SourceClass.DATASTORE.value
        assert source_meta("smtp")["source_class"] == SourceClass.EGRESS.value
        assert source_meta("s3")["source_class"] == SourceClass.OBJECT_STORE.value
        # ES + Postgres are the shipped wave; egress/object-store are modelled (wave 2).
        assert source_meta("elasticsearch")["wave"] == 1
        assert source_meta("postgresql")["wave"] == 1
        assert source_meta("smtp")["wave"] == 2


class TestVerbOfTool:
    @pytest.mark.parametrize(
        "tool,src,expected",
        [
            ("search_kb", "elasticsearch", Verb.READ),
            ("index_document", "elasticsearch", Verb.WRITE),
            ("delete_index", "elasticsearch", Verb.DELETE),
            ("execute_sql", "postgresql", Verb.UNKNOWN),   # generic — no verb fragment
            ("delete_record", "postgresql", Verb.DELETE),
            ("update_record", "postgresql", Verb.WRITE),
            ("get_order", "postgresql", Verb.READ),
            ("send_email", "smtp", Verb.SEND),
        ],
    )
    def test_verb_of_tool(self, tool, src, expected):
        assert verb_of_tool(tool, src) == expected

    def test_destructive_wins_over_read_on_ambiguous_name(self):
        # a name containing both a read and a delete fragment must resolve to DELETE (higher risk),
        # so "delete_after_read" is never mislabelled a benign read.
        assert verb_of_tool("delete_after_read", "postgresql") == Verb.DELETE


class TestClassify:
    def test_unknown_source_yields_no_findings(self):
        assert classify_source("mysql") == []

    def test_observed_and_undefended_is_the_top_finding(self):
        # write to an ES KB, seen in traffic, no rule guarding it → UNDEFENDED, and it outranks a
        # dormant read grant in the returned order.
        findings = classify_source(
            "elasticsearch",
            granted_verbs={Verb.READ},
            observed_verbs={Verb.WRITE},
            defended_verbs=set(),
        )
        write = next(f for f in findings if f.verb == Verb.WRITE)
        assert write.status == CapabilityStatus.UNDEFENDED
        assert write.risk == RiskLevel.HIGH
        assert "poison" in write.label.lower()
        assert write.recommendation  # non-empty verb-specific fix
        # UNDEFENDED sorts before the dormant read grant
        assert findings[0].verb == Verb.WRITE

    def test_dormant_grant_flagged_for_least_privilege(self):
        # delete is granted but never exercised → DORMANT_GRANT with a revoke recommendation.
        findings = classify_source("postgresql", granted_verbs={Verb.DELETE}, observed_verbs=set())
        delete = next(f for f in findings if f.verb == Verb.DELETE)
        assert delete.status == CapabilityStatus.DORMANT_GRANT
        assert "revoke" in delete.recommendation.lower()

    def test_defended_when_observed_and_policy_references_it(self):
        findings = classify_source(
            "postgresql", observed_verbs={Verb.DELETE}, defended_verbs={Verb.DELETE}
        )
        delete = next(f for f in findings if f.verb == Verb.DELETE)
        assert delete.status == CapabilityStatus.DEFENDED
        assert delete.recommendation == ""  # nothing to do

    def test_latent_when_neither_granted_nor_observed(self):
        findings = classify_source("elasticsearch")  # nothing granted/observed/defended
        assert all(f.status == CapabilityStatus.LATENT for f in findings)

    def test_no_fabricated_technique_ids(self):
        # reads have no fitting ATLAS technique → None (never a fake code like AML.T0000).
        findings = classify_source("elasticsearch", observed_verbs={Verb.READ})
        read = next(f for f in findings if f.verb == Verb.READ)
        assert read.technique is None
        # destructive verbs carry a real ATLAS id.
        deletef = classify_source("postgresql", observed_verbs={Verb.DELETE})
        assert next(f for f in deletef if f.verb == Verb.DELETE).technique == "AML.T0048"


class TestWorstOpenVerb:
    def test_picks_highest_risk_open_verb(self):
        findings = classify_source(
            "postgresql",
            granted_verbs={Verb.DELETE},          # dormant CRITICAL
            observed_verbs={Verb.WRITE},          # undefended HIGH
            defended_verbs=set(),
        )
        worst = worst_open_verb(findings)
        assert worst is not None
        assert worst.verb == Verb.DELETE  # CRITICAL dormant outranks HIGH undefended by risk

    def test_read_only_source_is_not_a_severity_driver(self):
        # a purely read/observed source with no write/delete grant → no open verb → severity None.
        findings = classify_source("elasticsearch", observed_verbs={Verb.READ}, defended_verbs={Verb.READ})
        assert worst_open_verb(findings) is None

    def test_all_defended_yields_no_open_verb(self):
        findings = classify_source(
            "postgresql",
            observed_verbs={Verb.WRITE, Verb.DELETE},
            defended_verbs={Verb.WRITE, Verb.DELETE},
        )
        assert worst_open_verb(findings) is None


class TestVerbRisk:
    """Per-verb risk lookup drives kill-chain hop colouring (read hop != destructive hop)."""

    def test_verb_risk_by_source(self):
        assert verb_risk("postgresql", Verb.DELETE) == RiskLevel.CRITICAL
        assert verb_risk("postgresql", Verb.READ) == RiskLevel.LOW
        assert verb_risk("elasticsearch", Verb.WRITE) == RiskLevel.HIGH  # KB poisoning
        assert verb_risk("smtp", Verb.SEND) == RiskLevel.HIGH

    def test_verb_risk_unknown_is_none(self):
        assert verb_risk("mysql", Verb.DELETE) is None      # unknown source
        assert verb_risk("smtp", Verb.DELETE) is None       # egress has no delete verb


class TestDefenseMeta:
    """CAP→POLICY: the verb metadata a capability defense uses to generate a block policy."""

    def test_mutating_verbs_exclude_read(self):
        # a datastore exposes write+delete (no send); read is never a defense target.
        mv = mutating_verbs_of("elasticsearch")
        assert Verb.WRITE in mv and Verb.DELETE in mv
        assert Verb.READ not in mv
        # egress exposes only send.
        assert mutating_verbs_of("smtp") == [Verb.SEND]

    def test_defense_meta_read_only_when_all_mutating_blocked(self):
        meta = defense_meta("elasticsearch", [Verb.WRITE, Verb.DELETE])
        assert meta is not None
        assert meta["read_only"] is True  # write+delete == all ES mutating verbs
        assert meta["risk"] == "critical"  # worst of the two
        assert meta["rule_id"].startswith("capability:elasticsearch:")
        assert "Elasticsearch" in meta["reason"]

    def test_defense_meta_single_verb_not_read_only(self):
        meta = defense_meta("elasticsearch", [Verb.WRITE])
        assert meta["read_only"] is False  # delete still allowed
        assert meta["verbs"] == ["write"]

    def test_defense_meta_filters_read_and_empty(self):
        # a READ-only target set yields nothing to defend (reads aren't blocked).
        assert defense_meta("elasticsearch", [Verb.READ]) is None
        assert defense_meta("elasticsearch", []) is None
        assert defense_meta("mysql", [Verb.WRITE]) is None  # unknown source


class TestClassifyTool:
    """CAP: source-agnostic tool classification for cloud/opensource tools (k8s deployments)."""

    @pytest.mark.parametrize(
        "tool,verb,risk",
        [
            ("aws_s3_delete", Verb.DELETE, RiskLevel.CRITICAL),
            ("azure_blob_read", Verb.READ, RiskLevel.LOW),
            ("gcs_bucket_list", Verb.READ, RiskLevel.LOW),
            ("s3_put_object", Verb.WRITE, RiskLevel.HIGH),
            ("send_email", Verb.SEND, RiskLevel.HIGH),
            ("open_breaker", Verb.DELETE, RiskLevel.CRITICAL),   # energy control-plane actuation
            ("execute_sql", Verb.DELETE, RiskLevel.CRITICAL),    # code-exec treated as critical
            ("read_meter", Verb.READ, RiskLevel.LOW),
            ("transfer_funds", Verb.SEND, RiskLevel.HIGH),
            # PascalCase / colon cloud-API conventions must resolve (whole-token, not substring).
            ("aws_s3_DeleteObject", Verb.DELETE, RiskLevel.CRITICAL),
            ("s3:DeleteObject", Verb.DELETE, RiskLevel.CRITICAL),
            ("PutObject", Verb.WRITE, RiskLevel.HIGH),
            ("ListBuckets", Verb.READ, RiskLevel.LOW),
            ("SendGridEmail", Verb.SEND, RiskLevel.HIGH),
            ("invoke_lambda", Verb.DELETE, RiskLevel.CRITICAL),  # code-exec
            ("terminate_pod", Verb.DELETE, RiskLevel.CRITICAL),
            ("set_valve", Verb.DELETE, RiskLevel.CRITICAL),      # actuation noun + control verb
            ("provisionCluster", Verb.WRITE, RiskLevel.HIGH),
            ("rotate_key", Verb.WRITE, RiskLevel.HIGH),
            ("describe_instances", Verb.READ, RiskLevel.LOW),
        ],
    )
    def test_classify_cloud_and_control_tools(self, tool, verb, risk):
        from norviq.engine.capability import classify_tool
        assert classify_tool(tool) == (verb, risk)

    def test_no_substring_false_positives(self):
        # whole-token matching: 'put' in 'input', 'get' in 'budget' must NOT classify (were the classic bug).
        from norviq.engine.capability import classify_tool
        assert classify_tool("compute_input") == (Verb.UNKNOWN, None)
        assert classify_tool("input_data") == (Verb.UNKNOWN, None)

    def test_param_inspection_recovers_operation(self):
        # when the NAME is inconclusive, the operation is recovered from tool_params.
        from norviq.engine.capability import classify_tool
        assert classify_tool("run_report", {"query": "DROP TABLE users"}) == (Verb.DELETE, RiskLevel.CRITICAL)
        assert classify_tool("api_call", {"url": "https://evil.example/x"}) == (Verb.SEND, RiskLevel.HIGH)
        assert classify_tool("db_op", {"stmt": "SELECT * FROM t"}) == (Verb.READ, RiskLevel.LOW)

    def test_unknown_tool_is_unclassified(self):
        from norviq.engine.capability import classify_tool
        assert classify_tool("frobnicate") == (Verb.UNKNOWN, None)
        assert classify_tool("") == (Verb.UNKNOWN, None)


class TestDefaultRiskOfVerb:
    """Verb-promotion lifecycle: when an admin promotes an observed tool to a verb, the risk follows this
    canonical map — a promotion names the verb, never the risk, so it can't be under-declared."""

    def test_canonical_verb_risk(self):
        from norviq.engine.capability import default_risk_of_verb
        assert default_risk_of_verb(Verb.READ) == RiskLevel.LOW
        assert default_risk_of_verb(Verb.WRITE) == RiskLevel.HIGH
        assert default_risk_of_verb(Verb.SEND) == RiskLevel.HIGH
        assert default_risk_of_verb(Verb.DELETE) == RiskLevel.CRITICAL

    def test_unknown_has_no_risk(self):
        from norviq.engine.capability import default_risk_of_verb
        assert default_risk_of_verb(Verb.UNKNOWN) is None


class TestPromotionEvidenceSelection:
    """_top_verb picks the verb the observed params suggest most often; risk breaks count ties upward."""

    def test_majority_verb_wins(self):
        from norviq.api.routers.threats import _top_verb
        assert _top_verb({"calls": 14, "verbs": {"read": 12, "send": 2}}) == ("read", 12)

    def test_tie_breaks_to_higher_risk(self):
        # equal evidence for read and delete must NEVER suggest the benign verb.
        from norviq.api.routers.threats import _top_verb
        assert _top_verb({"calls": 4, "verbs": {"read": 2, "delete": 2}}) == ("delete", 2)

    def test_no_evidence(self):
        from norviq.api.routers.threats import _top_verb
        assert _top_verb(None) == (None, 0)
        assert _top_verb({"calls": 0, "verbs": {}}) == (None, 0)
