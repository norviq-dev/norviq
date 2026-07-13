# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Canonical SHARED horizontal data-protection rules, composed into a sector pack's materialized
# (ns,__pack__) module when the pack's manifest `requires` them (finance -> pci, healthcare/government
# -> pii). One definition — kept byte-for-decision identical to comprehensive.rego (see
# tests/engine/test_shared_horizontal_parity or opa test) so a sector namespace gets the SAME PCI/PII
# coverage as the default policy without re-implementing it in each pack.
#
# v0 (--v0-compatible). Composable: each SHARED-RULE section contributes to the packs' shared
# blocks/reasons partial rules (the combiner extracts the requested sections by name; the RESOLVER
# here is only for standalone opa-test and is dropped when composed into a pack).
package norviq.sector.shared

# >>> SHARED-RULE pci
# PCI — PAN by field name or Luhn-valid value (mirrors comprehensive.rego).
pci_keys = {"cc_number", "card_number", "credit_card"}

# F-15: a PAN-named key at ANY depth (last path element is the immediate key).
blocks["pci_card_numbers"] {
    walk(input.tool_params, [path, _])
    count(path) > 0
    k := path[count(path) - 1]
    is_string(k)
    pci_keys[lower(k)]
}
blocks["pci_card_numbers"] {
    walk(input.tool_params, [_, val])
    is_string(val)
    regex.match(`^\d{13,19}$`, val)
    shared_luhn_valid(val)
}
blocks["pci_card_numbers"] {
    walk(input.tool_params, [_, val])
    is_string(val)
    candidate := regex.find_n(`\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}`, val, -1)[_]
    digits_only := regex.replace(candidate, `[ -]`, "")
    count(digits_only) == 16
    shared_luhn_valid(digits_only)
}
reasons["pci_card_numbers"] = "Payment card data (PAN) detected — PCI DSS"

shared_luhn_valid(s) {
    digits := [to_number(c) | c := regex.find_n(`[0-9]`, s, -1)[_]]
    n := count(digits)
    total := sum([x | some i; v := digits[i]; x := shared_luhn_digit(v, (n - 1 - i) % 2)])
    total % 10 == 0
}
shared_luhn_digit(d, parity) = d {
    parity == 0
}
shared_luhn_digit(d, parity) = doubled {
    parity == 1
    doubled := d * 2
    doubled <= 9
}
shared_luhn_digit(d, parity) = sub {
    parity == 1
    doubled := d * 2
    doubled > 9
    sub := doubled - 9
}
# >>> END SHARED-RULE pci

# >>> SHARED-RULE pii
# PII — SSN shapes in params (mirrors comprehensive.rego). F-15: walk() recurses nested objects/arrays.
blocks["pii_detection"] {
    walk(input.tool_params, [_, val])
    is_string(val)
    regex.match(`^(\d{3}-\d{2}-\d{4}|\d{4}-\d{2}-\d{2}|[A-Z]{2}\d{7})$`, val)
}
blocks["pii_detection"] {
    walk(input.tool_params, [_, val])
    is_string(val)
    regex.match(`\b\d{3}-\d{2}-\d{4}\b`, val)
}
reasons["pii_detection"] = "PII (SSN) detected in tool parameters"
# >>> END SHARED-RULE pii

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
