# Fleet architecture — the hub as a monitor + manage plane

**Status:** decision doc (the model the fleet code is built to). Companion to `fleet-enrollment.md` (join-token flow)
and `fleet-mgmt` (apply transparency, pack customization, centralized monitoring).

## The model
A **hub** centrally **monitors** and **manages** any number of **spoke** clusters. Each spoke is a normal
single-cluster Norviq install that has *enrolled* into the hub (see `fleet-enrollment.md`). The hub runs the
`norviq-fleet-api` deployment + its own Postgres; spokes run the usual `norviq-api` with the relay + puller enabled.

### The connection is SPOKE-INITIATED OUTBOUND
Every hub↔spoke interaction today is **initiated by the spoke, outbound**:
- **Enrollment** — `norviq fleet join <token>` → the spoke calls the hub once to claim its join token.
- **Heartbeat + rollups** — the relay POSTs to the hub every interval (cluster status, agent/audit rollups, and the
  bounded monitor detail added in this work).
- **Policy pull** — the puller GETs the hub's signed bundle, verifies it locally, and applies it.

The hub **never dials into a spoke.** This is the deliberate security posture and the **customer contract**:

> To enroll a cluster into a Norviq fleet you only need to **allow spoke→hub outbound (443)** and run
> `norviq fleet join`. **No inbound access to your cluster is required or requested.** The hub cannot reach your
> cluster's API, your workloads, or your data plane.

This keeps the blast radius asymmetric: a compromised hub cannot push commands into spokes out-of-band — it can only
publish a **signed** policy bundle that each spoke independently verifies (fail-closed on a bad signature) and pulls
on its own schedule. Live management (e.g. "apply this now" with an immediate ack) is a **roadmap reverse-channel**
(spoke-initiated long-poll / outbound stream), not an inbound hub→spoke socket.

## Three data classes
Every piece of cross-cluster data falls into one of three classes; the console's behavior follows from the class.

| Class | What | Where it lives | Hub behavior |
|---|---|---|---|
| **MONITOR** | Bounded read-detail safe to centralize: cluster status, agent list + trust, effective-policy summary, coverage %, asset/attack-graph **summaries** (counts, top-N). | Relayed to the hub as rollups/summaries; raw source stays in the spoke. | Render at the hub, **labeled with freshness** ("as of last heartbeat"). Fall back to deep-link when stale/unreachable. |
| **MANAGE** | Writes — policy create/apply, pack enable/edit, retract. | Authored at the hub (`fleet_policy`), distributed as a **signed bundle**, applied by the spoke on pull. | Already safe: the hub publishes; the spoke verifies + pulls + applies + **reports rollout state**. The console shows the manifest + propagation (distributed → pulled @vN → enforcing). |
| **RESIDENCY** | Raw audit records and anything a customer marks residency-restricted. | **Never leaves the spoke** (`Cluster.residency` / `NRVQ_FLEET_RESIDENCY`). Only counts/rollups are relayed. | **Deep-link only** — the hub links to the spoke's own console; it never shows raw audit centrally. |

The rule that ties it together: **a remote-cluster selection never renders or mutates LOCAL data under a remote
label.** MONITOR data is shown from hub rollups (honest, fresh-labeled); MANAGE happens via push-signed-policy (never a
direct write to the wrong cluster — enforced by the client guard `NRVQ-UI-4601`); RESIDENCY/raw stays a deep-link.

## What is built now vs roadmap
**Built now**
- Enrollment via hub-minted, single-use, scoped **join token** (`fleet-enrollment.md`); explicit remove/leave.
- Spoke→hub **rollups** (agent + audit) + **bounded monitor detail** (agent/effective-policy/coverage/graph
  summaries) → hub renders MONITOR pages for a remote cluster with freshness; deep-link fallback for raw/residency.
- **MANAGE** via signed policy push: author at hub → per-cluster signed bundle (RS256 trust root, fail-closed) →
  spoke pull + apply + **rollout reporting** (`pending|applied|failed|diverged`) → retract via the reconcile path.
- **Apply transparency**: the console shows the exact applied manifest + honest outcome + live propagation for both
  local apply and fleet push.
- **Honesty**: remote selection = hub-rollup-or-deep-link, never local-data-under-a-remote-label, and a hard
  client mutation guard.

**Roadmap (not built)**
- **Reverse-channel live manage** — a spoke-initiated outbound long-poll/stream so a hub operator gets an immediate
  apply ack / near-real-time push without weakening the no-inbound contract. Today propagation is pull-interval
  bounded (≤ one `fleet_pull_interval_s`).
- Centralizing additional MONITOR detail beyond the bounded summaries (always rollups, never raw audit — RESIDENCY is
  permanent).

## Honesty rules (non-negotiable)
- Never show a spoke's stale data as if it were live — **label freshness**, and deep-link when stale/unreachable.
- Never render raw audit centrally for a residency-restricted spoke — **deep-link**.
- Never describe a mechanism as something it isn't — a policy apply is a **policy-store write + engine load** (and, for
  fleet, a **signed bundle the spoke pulls**); it is **not** a `kubectl apply` of a CRD.
