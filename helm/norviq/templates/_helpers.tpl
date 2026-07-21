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
{{- define "norviq.waitFor" -}}
- name: {{ .name }}
  image: busybox:1.36
  command: ['sh','-c','until nc -z {{ .host }} {{ .port }}; do echo waiting for {{ .host }}; sleep 2; done']
  securityContext:
    runAsNonRoot: true
    runAsUser: 65534
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
