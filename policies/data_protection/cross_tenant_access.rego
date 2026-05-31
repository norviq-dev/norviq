# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.data_protection.cross_tenant_access

import rego.v1

default allow := false
default decision := "allow"

agent_namespace := input.agent_identity.namespace

has_different_tenant if {
    tenant := input.tool_params.tenant_id
    tenant != agent_namespace
}

has_different_namespace if {
    ns := input.tool_params.namespace
    ns != agent_namespace
}

decision := "block" if has_different_tenant
decision := "block" if has_different_namespace

allow if decision == "allow"

rule_id := "cross_tenant_access" if has_different_tenant
rule_id := "cross_namespace_access" if { not has_different_tenant; has_different_namespace }
rule_id := "default_allow" if { not has_different_tenant; not has_different_namespace }

reason := sprintf("Cross-tenant access: agent in %s, accessing tenant %s", [agent_namespace, input.tool_params.tenant_id]) if has_different_tenant
reason := sprintf("Cross-namespace access: agent in %s, accessing namespace %s", [agent_namespace, input.tool_params.namespace]) if {
    not has_different_tenant
    has_different_namespace
}
reason := "Allowed" if { not has_different_tenant; not has_different_namespace }
