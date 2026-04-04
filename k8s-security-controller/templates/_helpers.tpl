{{/*
Expand the name of the chart.
*/}}
{{- define "k8s-security-controller.name" -}}
{{- .Values.nameOverride | default .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "k8s-security-controller.fullname" -}}
{{- .Values.fullnameOverride | default .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "k8s-security-controller.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "k8s-security-controller.labels" -}}
helm.sh/chart: {{ include "k8s-security-controller.chart" . }}
{{ include "k8s-security-controller.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/*
Selector labels
*/}}
{{- define "k8s-security-controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "k8s-security-controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
