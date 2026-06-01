# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.data_protection.cross_tenant_access_test

import rego.v1
import data.norviq.data_protection.cross_tenant_access

test_blocks_cross_tenant_access if {
    result := cross_tenant_access.decision with input as {
        "tool_name": "read_customer",
        "tool_params": {"tenant_id": "payments", "id": "123"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "support", "agent_class": "test"},
        "session_id": "sess-a",
        "trust_score": 0.9,
        "call_count": 1,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "block"
}

test_blocks_cross_namespace_access if {
    result := cross_tenant_access.decision with input as {
        "tool_name": "read_customer",
        "tool_params": {"namespace": "payments", "id": "123"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "support", "agent_class": "test"},
        "session_id": "sess-b",
        "trust_score": 0.9,
        "call_count": 2,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "block"
}

test_allows_same_namespace if {
    trigger_input := {
        "tool_name": "read_customer",
        "tool_params": {"namespace": "support", "id": "123"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "support", "agent_class": "test"},
        "session_id": "sess-c",
        "trust_score": 0.9,
        "call_count": 3,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    cross_tenant_access.decision with input as trigger_input == "allow"
    cross_tenant_access.reason with input as trigger_input == "Allowed"
}
