# The "permissive" preset: allow by default, escalating only low-trust requests
# (trust_score < 0.4). The lightest of the three org baselines.
package norviq.presets.permissive

default decision = "allow"

decision = "escalate" {
  input.trust_score < 0.4
}

rule_id = "permissive_low_trust_escalate" {
  decision == "escalate"
}

reason = "Permissive preset escalated low-trust request" {
  decision == "escalate"
}

rule_id = "permissive_default_allow" {
  decision == "allow"
}

reason = "Permissive preset allowed request" {
  decision == "allow"
}
