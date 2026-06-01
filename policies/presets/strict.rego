# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.presets.strict

import rego.v1
import data.norviq.owasp.llm01_prompt_injection
import data.norviq.owasp.llm02_data_leakage
import data.norviq.owasp.llm05_supply_chain
import data.norviq.owasp.llm06_excessive_agency
import data.norviq.owasp.llm10_unbounded_consumption
import data.norviq.data_protection.pii_detection
import data.norviq.data_protection.pci_card_numbers
import data.norviq.data_protection.hipaa_phi
import data.norviq.data_protection.cross_tenant_access
import data.norviq.data_protection.data_exfiltration
import data.norviq.access_control.deny_write_operations
import data.norviq.access_control.deny_delete_operations
import data.norviq.access_control.deny_admin_tools
import data.norviq.access_control.namespace_isolation
import data.norviq.tool_safety.deny_sql_injection
import data.norviq.tool_safety.deny_shell_execution
import data.norviq.tool_safety.deny_file_system_access
import data.norviq.tool_safety.deny_network_calls
import data.norviq.tool_safety.deny_wildcard_operations
import data.norviq.rate_limiting.calls_per_minute
import data.norviq.rate_limiting.burst_detection
import data.norviq.rate_limiting.session_limit
import data.norviq.rate_limiting.daily_quota
import data.norviq.trust.low_trust_escalate
import data.norviq.trust.frozen_agent_block
import data.norviq.trust.new_agent_audit
import data.norviq.trust.trust_decay
import data.norviq.industry.finance.deny_trading_tools
import data.norviq.industry.finance.audit_all_transactions
import data.norviq.industry.healthcare.deny_patient_data_tools
import data.norviq.industry.healthcare.audit_phi_access
import data.norviq.industry.ecommerce.deny_price_modification
import data.norviq.industry.ecommerce.audit_order_changes

default allow := false
default decision := "allow"

has_block if llm01_prompt_injection.decision == "block"
has_block if llm02_data_leakage.decision == "block"
has_block if llm05_supply_chain.decision == "block"
has_block if llm06_excessive_agency.decision == "block"
has_block if llm10_unbounded_consumption.decision == "block"
has_block if pii_detection.decision == "block"
has_block if pci_card_numbers.decision == "block"
has_block if hipaa_phi.decision == "block"
has_block if cross_tenant_access.decision == "block"
has_block if data_exfiltration.decision == "block"
has_block if deny_write_operations.decision == "block"
has_block if deny_delete_operations.decision == "block"
has_block if deny_admin_tools.decision == "block"
has_block if namespace_isolation.decision == "block"
has_block if deny_sql_injection.decision == "block"
has_block if deny_shell_execution.decision == "block"
has_block if deny_file_system_access.decision == "block"
has_block if deny_network_calls.decision == "block"
has_block if deny_wildcard_operations.decision == "block"
has_block if calls_per_minute.decision == "block"
has_block if burst_detection.decision == "block"
has_block if session_limit.decision == "block"
has_block if daily_quota.decision == "block"
has_block if low_trust_escalate.decision == "block"
has_block if frozen_agent_block.decision == "block"
has_block if new_agent_audit.decision == "block"
has_block if trust_decay.decision == "block"
has_block if deny_trading_tools.decision == "block"
has_block if audit_all_transactions.decision == "block"
has_block if deny_patient_data_tools.decision == "block"
has_block if audit_phi_access.decision == "block"
has_block if deny_price_modification.decision == "block"
has_block if audit_order_changes.decision == "block"

has_escalate if llm01_prompt_injection.decision == "escalate"
has_escalate if llm02_data_leakage.decision == "escalate"
has_escalate if llm05_supply_chain.decision == "escalate"
has_escalate if llm06_excessive_agency.decision == "escalate"
has_escalate if llm10_unbounded_consumption.decision == "escalate"
has_escalate if pii_detection.decision == "escalate"
has_escalate if pci_card_numbers.decision == "escalate"
has_escalate if hipaa_phi.decision == "escalate"
has_escalate if cross_tenant_access.decision == "escalate"
has_escalate if data_exfiltration.decision == "escalate"
has_escalate if deny_write_operations.decision == "escalate"
has_escalate if deny_delete_operations.decision == "escalate"
has_escalate if deny_admin_tools.decision == "escalate"
has_escalate if namespace_isolation.decision == "escalate"
has_escalate if deny_sql_injection.decision == "escalate"
has_escalate if deny_shell_execution.decision == "escalate"
has_escalate if deny_file_system_access.decision == "escalate"
has_escalate if deny_network_calls.decision == "escalate"
has_escalate if deny_wildcard_operations.decision == "escalate"
has_escalate if calls_per_minute.decision == "escalate"
has_escalate if burst_detection.decision == "escalate"
has_escalate if session_limit.decision == "escalate"
has_escalate if daily_quota.decision == "escalate"
has_escalate if low_trust_escalate.decision == "escalate"
has_escalate if frozen_agent_block.decision == "escalate"
has_escalate if new_agent_audit.decision == "escalate"
has_escalate if trust_decay.decision == "escalate"
has_escalate if deny_trading_tools.decision == "escalate"
has_escalate if audit_all_transactions.decision == "escalate"
has_escalate if deny_patient_data_tools.decision == "escalate"
has_escalate if audit_phi_access.decision == "escalate"
has_escalate if deny_price_modification.decision == "escalate"
has_escalate if audit_order_changes.decision == "escalate"

has_audit if llm01_prompt_injection.decision == "audit"
has_audit if llm02_data_leakage.decision == "audit"
has_audit if llm05_supply_chain.decision == "audit"
has_audit if llm06_excessive_agency.decision == "audit"
has_audit if llm10_unbounded_consumption.decision == "audit"
has_audit if pii_detection.decision == "audit"
has_audit if pci_card_numbers.decision == "audit"
has_audit if hipaa_phi.decision == "audit"
has_audit if cross_tenant_access.decision == "audit"
has_audit if data_exfiltration.decision == "audit"
has_audit if deny_write_operations.decision == "audit"
has_audit if deny_delete_operations.decision == "audit"
has_audit if deny_admin_tools.decision == "audit"
has_audit if namespace_isolation.decision == "audit"
has_audit if deny_sql_injection.decision == "audit"
has_audit if deny_shell_execution.decision == "audit"
has_audit if deny_file_system_access.decision == "audit"
has_audit if deny_network_calls.decision == "audit"
has_audit if deny_wildcard_operations.decision == "audit"
has_audit if calls_per_minute.decision == "audit"
has_audit if burst_detection.decision == "audit"
has_audit if session_limit.decision == "audit"
has_audit if daily_quota.decision == "audit"
has_audit if low_trust_escalate.decision == "audit"
has_audit if frozen_agent_block.decision == "audit"
has_audit if new_agent_audit.decision == "audit"
has_audit if trust_decay.decision == "audit"
has_audit if deny_trading_tools.decision == "audit"
has_audit if audit_all_transactions.decision == "audit"
has_audit if deny_patient_data_tools.decision == "audit"
has_audit if audit_phi_access.decision == "audit"
has_audit if deny_price_modification.decision == "audit"
has_audit if audit_order_changes.decision == "audit"

decision := "block" if has_block
decision := "escalate" if { not has_block; has_escalate }
decision := "audit" if { not has_block; not has_escalate; has_audit }

allow if decision == "allow"
rule_id := "strict_preset"
reason := "Strict preset evaluated"
