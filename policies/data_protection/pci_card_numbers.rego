# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.data_protection.pci_card_numbers

import rego.v1

default allow := false
default decision := "allow"

card_patterns := ["card_number", "credit_card", "cc_number", "pan", "card_num", "cvv", "cvc", "expiry"]

has_card_data if {
    some k
    input.tool_params[k]
    pattern := card_patterns[_]
    contains(lower(k), pattern)
}

has_card_value if {
    val := input.tool_params[_]
    is_string(val)
    candidate := regex.find_n(`\d{13,19}`, val, -1)[_]
    luhn_valid(candidate)
}

# Luhn (mod-10) gate so non-card 13-19 digit ids (invoice/order numbers) are not
# flagged as card data — keeps the PCI rule's false-positive rate near zero.
luhn_valid(s) if {
    digits := [to_number(c) | c := regex.find_n(`[0-9]`, s, -1)[_]]
    n := count(digits)
    total := sum([x | some i; v := digits[i]; x := luhn_digit(v, (n - 1 - i) % 2)])
    total % 10 == 0
}

luhn_digit(d, parity) := d if parity == 0
luhn_digit(d, parity) := d * 2 if {
    parity == 1
    d * 2 <= 9
}
luhn_digit(d, parity) := (d * 2) - 9 if {
    parity == 1
    d * 2 > 9
}

decision := "block" if has_card_data
decision := "block" if has_card_value

allow if decision == "allow"

rule_id := "pci_card_field" if has_card_data
rule_id := "pci_card_number" if { not has_card_data; has_card_value }
rule_id := "default_allow" if { not has_card_data; not has_card_value }

reason := "Payment card data field detected - PCI DSS violation" if has_card_data
reason := "Possible card number detected in parameters" if { not has_card_data; has_card_value }
reason := "Allowed" if { not has_card_data; not has_card_value }
