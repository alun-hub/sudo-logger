{{/* Expand the name of the chart. */}}
{{- define "sudo-logger.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Create a default fully qualified app name. */}}
{{- define "sudo-logger.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Common labels */}}
{{- define "sudo-logger.labels" -}}
helm.sh/chart: {{ include "sudo-logger.chart" . }}
{{ include "sudo-logger.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Selector labels */}}
{{- define "sudo-logger.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sudo-logger.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Create chart name and version as used by the chart label. */}}
{{- define "sudo-logger.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Name of the Secret holding ca.crt/tls.crt/tls.key. */}}
{{- define "sudo-logger.tlsSecretName" -}}
{{- .Values.tls.existingSecret | default (printf "%s-tls" (include "sudo-logger.fullname" .)) -}}
{{- end }}

{{/* Name of the Secret holding ack-sign.key. */}}
{{- define "sudo-logger.signingKeySecretName" -}}
{{- .Values.signingKey.existingSecret | default (printf "%s-signing-key" (include "sudo-logger.fullname" .)) -}}
{{- end }}

{{/* PostgreSQL host (bundled subchart's service name, or a user-provided host). */}}
{{- define "sudo-logger.dbHost" -}}
{{- .Values.storage.distributed.dbHost | default (printf "%s-postgresql" .Release.Name) -}}
{{- end }}

{{/* MinIO/S3 endpoint (bundled subchart's service, or a user-provided endpoint). */}}
{{- define "sudo-logger.s3Endpoint" -}}
{{- .Values.storage.distributed.s3.endpoint | default (printf "http://%s-minio:9000" .Release.Name) -}}
{{- end }}

{{/* Name of the Secret holding the JIT approval REST API bearer token. */}}
{{- define "sudo-logger.approvalTokenSecretName" -}}
{{- .Values.approval.existingTokenSecret | default (printf "%s-approval-token" (include "sudo-logger.fullname" .)) -}}
{{- end }}

{{/* Name of the ConfigMap holding approval-policy.yaml. */}}
{{- define "sudo-logger.approvalPolicyConfigMapName" -}}
{{- .Values.approval.existingPolicyConfigMap | default (printf "%s-approval-policy" (include "sudo-logger.fullname" .)) -}}
{{- end }}
