# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.owasp.llm05_supply_chain

import rego.v1

default allow := false
default decision := "allow"

risky_tools := ["load_plugin", "install_package", "import_module", "eval", "exec", "download_script"]
risky_url_patterns := ["pastebin", "gist.github", "raw.githubusercontent", "hastebin"]

is_risky_tool if input.tool_name == risky_tools[_]

has_risky_url if {
    val := input.tool_params[_]
    is_string(val)
    pattern := risky_url_patterns[_]
    contains(lower(val), pattern)
}

decision := "block" if is_risky_tool
decision := "block" if has_risky_url

allow if decision == "allow"

rule_id := "llm05_supply_chain_tool" if is_risky_tool
rule_id := "llm05_supply_chain_url" if { not is_risky_tool; has_risky_url }
rule_id := "default_allow" if { not is_risky_tool; not has_risky_url }

reason := "Untrusted code execution tool blocked" if is_risky_tool
reason := "Risky URL pattern detected" if { not is_risky_tool; has_risky_url }
reason := "Allowed" if { not is_risky_tool; not has_risky_url }
