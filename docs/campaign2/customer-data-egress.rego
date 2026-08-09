package norviq.custom.customer_data_egress

# Customer records may only be sent to a mailbox the company controls.
#
# This closes the confused-deputy path: a caller talks a support agent into "confirming" a record to
# an address the caller supplies. Every individual step is legitimate -- read a customer, send an
# email -- so no content detector fires: the payload is a name and an email address, not an SSN or a
# credential. The only thing that marks it as exfiltration is the DESTINATION, so that is what this
# reads. pii_detection cannot do this even at deny; it matches SSN-shaped values only.

default decision = "allow"
default rule_id = "cde_default_allow"
default reason = "Allowed"

# Mailboxes the company controls. Everything else is an untrusted sink.
trusted_recipient_domains = {"acme.example.com", "acme-corp.example.com"}

egress_tools = {"send_email", "post_webhook", "upload_file", "send_message"}

# Addresses under a RECIPIENT key, at any depth -- not every address in the payload.
#
# Scanning every string was the first cut and it is wrong: a customer record legitimately CONTAINS
# the customer's own address, so forwarding one to a colleague would be blocked on the data rather
# than the destination. The same distinction strict.rego draws with `destination_keys`: a recipient
# argument is where the call is SENDING, a body is what it is sending.
#
# Walking the path rather than the leaf key keeps arrays working: `payload.cc[0]` has path
# ["payload","cc",0], whose last element is an index, so match if ANY path element is a recipient key.
recipient_keys = {"to", "cc", "bcc", "recipient", "recipients", "destination", "address", "email_to"}

recipient_domains[domain] {
  egress_tools[input.tool_name]
  walk(input.tool_params, [path, val])
  is_string(val)
  some i
  recipient_keys[lower(sprintf("%v", [path[i]]))]
  addr := regex.find_n(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`, val, -1)[_]
  domain := lower(split(addr, "@")[1])
}

untrusted_domains[d] {
  d := recipient_domains[_]
  not trusted_recipient_domains[d]
}

blocks["customer_data_to_untrusted_recipient"] {
  untrusted_domains[_]
}

reasons = {
  "customer_data_to_untrusted_recipient": "Blocked: customer data addressed to a domain the company does not control",
  "cde_default_allow": "Allowed",
}

block_fired { blocks[_] }
decision = "block" { block_fired }
rule_id = sort([id | blocks[id]])[0] { block_fired }
reason = reasons[rule_id]
