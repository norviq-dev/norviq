# Norviq — Asset Graph onboarding

The Asset Graph shows your agents, the tools they call, and the data those tools reach — one node per
agent identity, one per tool, one per data store — with edges colored by the real allow/block/escalate
decisions Norviq recorded. This page covers how to lay out namespaces and identities so the graph reads
cleanly, and what the multi-namespace view shows.

## Multi-namespace visibility
- **All namespaces (default).** The graph opens on **All namespaces**: every namespace you're permitted
  to see is unioned into one view, each namespace **clustered and color-coded**. Pick a single namespace
  from the **Namespace** dropdown to focus; **Agent class** filters within the view.
- **Scoping is enforced server-side.** An admin sees every namespace; a namespace-scoped viewer only ever
  sees its own — "All namespaces" resolves to just that viewer's namespace, and naming another namespace
  is refused. You never see another tenant's assets.
- **Cluster dropdown** appears **only in a multi-cluster / hub install** (when a fleet hub is configured).
  Single-cluster installs show no cluster control at all.

## Awaiting first tool call
An agent that is **deployed** (it has a policy and/or a registered identity) but has **not yet made a tool
call** is not invisible — it renders **dimmed with a dashed ring** and a "N deployed, awaiting first tool
call" hint. Once it makes its first observed call it joins the live graph. This is expected right after a
rollout; if an agent stays dimmed, it isn't reaching Norviq (check sidecar injection / the API URL).

## One chatbot = one identity (avoid collapse)
Agent nodes are keyed by **SPIFFE ID** — `spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>` —
which is derived from the pod's **namespace + service account**. The **agent class** (from the
`norviq.io/agent-class` pod label) is a label on that identity, not part of the key.

**Give each distinct chatbot its own identity.** Run it in **its own namespace, or under its own service
account**, with **one `agent_class`**. Then each chatbot is one clean node.

If two different chatbots share **one** namespace **and** service account (same SPIFFE ID) but carry
**different** `agent_class` labels, they'd otherwise collapse into a single node. Norviq avoids the silent
collapse: it renders a shared **identity node** with a distinguishable **sub-node per agent class**
(linked by a "belongs to" edge), and both classes appear in the Agent-class filter. This keeps you honest
about a misconfiguration — but the fix is to give each chatbot its own service account or namespace so it
maps to its own identity.

**Recommended layout**

| Chatbot | Namespace | Service account | agent_class |
|---|---|---|---|
| Payments assistant | `payments-bot` | `payments-sa` | `payments` |
| Support assistant  | `support-bot`  | `support-sa`  | `customer-support` |
| HR assistant       | `hr-bot`       | `hr-sa`       | `chatbot` |

Each row → one SPIFFE identity → one agent node. Deploy them, and they appear in **All namespaces**,
clustered by namespace, dimmed until their first tool call.
