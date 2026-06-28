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
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 }}
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
