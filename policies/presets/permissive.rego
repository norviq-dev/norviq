# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.presets.permissive

import rego.v1

default allow := false
default decision := "audit"

allow if false
rule_id := "permissive_preset"
reason := "Permissive mode - all calls audited"
