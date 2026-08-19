{{- define "norviq.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "norviq.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- printf "%s" $name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "norviq.labels" -}}
app.kubernetes.io/name: {{ include "norviq.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/part-of: norviq
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 }}
{{- end }}

{{/*
Selector labels — a STABLE subset that never changes across releases, so it is safe in
spec.selector.matchLabels (selector labels are IMMUTABLE on a live Deployment/StatefulSet). Kept
separate from norviq.labels precisely because that set includes app.kubernetes.io/version +
helm.sh/chart, which change every release and must NEVER go in a selector.

NOTE: the existing workloads select on `app: norviq-<component>` (immutable, cannot be changed on
the live release). This helper is used on Service selectors and is the intended matchLabels for any
NEW workload / a future chart major that re-creates the Deployments.
*/}}
{{- define "norviq.selectorLabels" -}}
app.kubernetes.io/name: {{ include "norviq.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Full label set for one component: norviq.labels + app.kubernetes.io/component. Additive to metadata
(never selectors). Usage: {{ include "norviq.componentLabels" (dict "root" $ "component" "api") | nindent N }}
*/}}
{{- define "norviq.componentLabels" -}}
{{ include "norviq.labels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Fully-qualified image reference for one Norviq component.
  Usage: {{ include "norviq.image" (dict "root" $ "component" .Values.images.api) }}

A `digest` wins over `tag` when set. That is what makes a RELEASED chart reproducible: the release
workflow rewrites images.<c>.digest to the immutable sha256 of the image it just built, so
`helm install --version X` deploys exactly the binaries that were built, scanned and signed for X —
not whatever a floating tag points at today. Installing from a source checkout leaves digest empty
and falls back to the readable tag, which is what you want while developing.
*/}}
{{- define "norviq.image" -}}
{{- $ref := printf "%s%s" .root.Values.images.registry .component.repository -}}
{{- if .component.digest -}}
{{- printf "%s@%s" $ref .component.digest -}}
{{- else -}}
{{- printf "%s:%s" $ref .component.tag -}}
{{- end -}}
{{- end }}

{{/*
Third-party (upstream) image ref, with the optional global.imageRegistry mirror host prepended for
air-gapped installs. Norviq's own images go through norviq.image (images.registry); this covers the
images with no registry field of their own — opa, redis, postgres, the tls-proxy nginx, the
cert-bootstrap job, the helm-test curl. Empty global => the upstream ref is unchanged.
  Usage: {{ include "norviq.thirdPartyImage" (dict "root" $ "image" "redis:7-alpine") }}
*/}}
{{- define "norviq.thirdPartyImage" -}}
{{- $g := .root.Values.global.imageRegistry | default "" -}}
{{- if $g -}}{{ printf "%s/%s" (trimSuffix "/" $g) .image }}{{- else -}}{{ .image }}{{- end -}}
{{- end }}

{{/* imagePullSecrets block (empty when .Values.imagePullSecrets is []). Usage: indent under spec. */}}
{{- define "norviq.imagePullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
{{ toYaml . }}
{{- end }}
{{- end }}

{{/* preStop sleep + terminationGracePeriod for graceful drain. Usage at container level (lifecycle). */}}
{{- define "norviq.preStop" -}}
{{- if gt (int .Values.gracefulShutdown.preStopSleepSeconds) 0 }}
lifecycle:
  preStop:
    exec:
      command: ["/bin/sh", "-c", "sleep {{ .Values.gracefulShutdown.preStopSleepSeconds }}"]
{{- end }}
{{- end }}

{{/* podAntiAffinity + topologySpread to spread replicas across nodes. Arg: dict app + root context.
     Usage: {{- include "norviq.spread" (dict "app" "norviq-api" "ctx" $) | nindent 6 }} */}}
{{- define "norviq.spread" -}}
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          topologyKey: kubernetes.io/hostname
          labelSelector:
            matchLabels:
              app: {{ .app }}
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: kubernetes.io/hostname
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        app: {{ .app }}
{{- end }}

{{/*
Hardened dependency wait-loop init container.

Every workload used to inline its own `busybox nc -z` loop with NO securityContext and NO resources —
so the one container that runs BEFORE the hardened app container was the least hardened thing in the
pod, and an unbounded one could drag the enforcement pod's QoS class down. The webhook's wait-for-api
was the only one done correctly; this makes that shape the single definition.

`nc -z` opens a TCP socket and nothing else: it needs no root, no capabilities, and no filesystem
writes, so the strict profile below is free.

Usage: {{- include "norviq.waitFor" (dict "name" "wait-for-postgres" "host" "norviq-postgresql" "port" 5432) | nindent 8 }}
*/}}
{{/*
The datastore hosts, resolved ONCE. Three configurations render three different names and every
consumer must agree on which — the connection URL, the readiness gate, everything:

  bundled (default)  -> norviq-postgresql / norviq-redis        (the in-chart StatefulSets)
  HA operators       -> postgresql.ha.serviceName / redis.ha.serviceName
  bring-your-own     -> postgresql.host / redis.host

They did NOT agree. secret.yaml computed this correctly for NRVQ_PG_URL/NRVQ_REDIS_URL while the
init containers hard-coded the BUNDLED names, so under HA those Services exist with no endpoints and
under an external datastore they are not rendered at all. Either way `until nc -z norviq-postgresql`
never returns and every api/engine pod sits in Init forever — with both datastores perfectly
healthy. Only the bundled default worked. Deriving both from here is the fix; keeping the logic in
one place is what stops it drifting apart again.
*/}}
{{- /* In-cluster names are FULLY QUALIFIED. NRVQ_PG_URL / NRVQ_REDIS_URL are not read only by
       pods in the release namespace: the webhook hands them verbatim to every sidecar it injects in
       `embedded` mode, and those pods live in TENANT namespaces where a bare `norviq-redis` does not
       resolve. Embedded sidecars crash-looped on
       `Error -2 connecting to norviq-redis:6379. Name or service not known`. An FQDN resolves
       identically from inside the release namespace, so qualifying costs nothing and fixes the
       cross-namespace case. A user-supplied .host is passed through untouched — it is already
       absolute and may be outside the cluster entirely. */}}
{{- define "norviq.pgHost" -}}
{{- if .Values.postgresql.host -}}
{{- .Values.postgresql.host -}}
{{- else -}}
{{- printf "%s.%s.svc.cluster.local" (ternary .Values.postgresql.ha.serviceName "norviq-postgresql" .Values.postgresql.ha.enabled) .Release.Namespace -}}
{{- end -}}
{{- end -}}

{{/*
Effective DB SSL mode.

The chart shipped two defaults that could not both hold: `postgresql.enabled: true` (the in-chart
StatefulSet, which has NO TLS listener — nothing in the chart ever gives it a cert) and
`config.dbSslMode: require`. So `helm install` with pure defaults could not start:

    ConnectionError: PostgreSQL server at "norviq-postgresql...:5432" rejected SSL upgrade
    ERROR:    Application startup failed. Exiting.

…which is the FIRST thing a new operator does. Four docs and the release gate all carried
`--set config.dbSslMode=disable` to work around it.

An explicit `config.dbSslMode` is honoured verbatim, always. Left empty it is derived, and the
derivation can only ever relax the ONE target where `require` is unsatisfiable by construction:

    bundled StatefulSet   disable   no TLS listener exists; `require` can only crash
    HA (CloudNativePG)    require   CNPG issues server certs and serves TLS
    external host         require   assume a managed/TLS-terminating Postgres

A managed database therefore still gets `require` with no action from the operator, which is the
posture that matters. `values-prod.yaml` pins it explicitly regardless.
*/}}
{{- define "norviq.dbSslMode" -}}
{{- if .Values.config.dbSslMode -}}
{{- .Values.config.dbSslMode -}}
{{- else if and .Values.postgresql.enabled (not .Values.postgresql.ha.enabled) (not .Values.postgresql.host) -}}
disable
{{- else -}}
require
{{- end -}}
{{- end -}}

{{- define "norviq.redisHost" -}}
{{- if .Values.redis.host -}}
{{- .Values.redis.host -}}
{{- else -}}
{{- printf "%s.%s.svc.cluster.local" (ternary .Values.redis.ha.serviceName "norviq-redis" .Values.redis.ha.enabled) .Release.Namespace -}}
{{- end -}}
{{- end -}}

{{/*
The host the READINESS GATE waits on, which is not always the host the URL uses.

Three cases, and the third is the one that was missing:
  explicit .host            -> wait on it
  bundled StatefulSet       -> wait on the in-chart Service
  external, no .host        -> "" — unknowable at template time, so do not wait at all

`norviq.pgHost` deliberately still falls back to the bundled name because NRVQ_PG_URL needs *a*
value; the gate must not inherit that fallback, because a name that will never resolve turns a
successful install into a permanent Init:0/2.
*/}}
{{- define "norviq.pgWaitHost" -}}
{{- if .Values.postgresql.host -}}
{{- .Values.postgresql.host -}}
{{- else if .Values.postgresql.enabled -}}
{{- printf "%s.%s.svc.cluster.local" (ternary .Values.postgresql.ha.serviceName "norviq-postgresql" .Values.postgresql.ha.enabled) .Release.Namespace -}}
{{- end -}}
{{- end -}}

{{- define "norviq.redisWaitHost" -}}
{{- if .Values.redis.host -}}
{{- .Values.redis.host -}}
{{- else if .Values.redis.enabled -}}
{{- printf "%s.%s.svc.cluster.local" (ternary .Values.redis.ha.serviceName "norviq-redis" .Values.redis.ha.enabled) .Release.Namespace -}}
{{- end -}}
{{- end -}}

{{/*
An EMPTY .host renders NO init container.

The gate can only wait on an address it can name. With an external datastore configured the
documented way — `enabled: false` + `existingSecret`, no `host` — the address lives inside the
Secret's URL and the chart cannot see it at template time.

That case rendered `until nc -z norviq-postgresql.<ns>.svc.cluster.local 5432`: the BUNDLED name, for
a Service `enabled: false` never creates. `helm install` reported success and every api and engine
pod then sat in Init:0/2 indefinitely, holding a perfectly good external URL it was never allowed to
try. The comment above about resolving the hosts in one place fixed the HA and explicit-host cases
and did not reach this one, because `norviq.pgHost` keys only off `.Values.postgresql.host`.
values.yaml made it worse by telling operators that with `existingSecret` the other keys "are then
unused" — `host` was still being used, here.

Skipping is safe. This gate is a convenience that avoids a few CrashLoopBackOffs while the bundled
StatefulSets come up; it is not a correctness mechanism. The app retries its own connections, and a
managed datastore is up before the release is installed. Waiting on a name that cannot resolve is
strictly worse than not waiting.
*/}}
{{- define "norviq.waitFor" -}}
{{- if .host -}}
- name: {{ .name }}
  image: busybox:1.36
  command: ['sh','-c','until nc -z {{ .host }} {{ .port }}; do echo waiting for {{ .host }}; sleep 2; done']
  securityContext:
    runAsNonRoot: true
    {{- if not (and .root .root.Values.openshift.enabled) }}
    {{- /* Omitted under OpenShift, which assigns a UID from the namespace range and rejects any
           pinned value. `and .root` keeps this safe if a call site forgets to thread the root ctx. */}}
    runAsUser: 65534
    {{- end }}
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: ["ALL"]
    seccompProfile:
      type: RuntimeDefault
  resources:
    requests:
      cpu: 10m
      memory: 16Mi
    limits:
      cpu: 50m
      memory: 32Mi
{{- end -}}
{{- end -}}

{{/*
Datastore URL env for BYO (existingSecret) stores.

An explicit `env:` entry WINS over `envFrom`, so when the operator owns the credential we simply
override NRVQ_PG_URL / NRVQ_REDIS_URL on the pod from THEIR Secret. The value never touches values,
`--set` or the chart's own Secret — kubelet resolves it at pod start. Renders nothing when both stores
are chart-managed, so the default path is byte-identical to before.
*/}}
{{- define "norviq.datastoreUrlEnv" -}}
{{- if ne (.Values.postgresql.existingSecret | default "") "" }}
- name: NRVQ_PG_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.postgresql.existingSecret | quote }}
      key: {{ .Values.postgresql.existingSecretKey | default "url" | quote }}
{{- end }}
{{- if ne (.Values.redis.existingSecret | default "") "" }}
- name: NRVQ_REDIS_URL
  valueFrom:
    secretKeyRef:
      name: {{ .Values.redis.existingSecret | quote }}
      key: {{ .Values.redis.existingSecretKey | default "url" | quote }}
{{- end }}
{{- end -}}
