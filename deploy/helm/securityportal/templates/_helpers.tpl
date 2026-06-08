{{/*
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Tommy Lehmann

Common helper templates for the securityportal chart.
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "securityportal.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncate at 63 chars because Kubernetes DNS names are limited to this.
*/}}
{{- define "securityportal.fullname" -}}
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

{{/*
Create chart label.
*/}}
{{- define "securityportal.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels applied to all resources.
*/}}
{{- define "securityportal.labels" -}}
helm.sh/chart: {{ include "securityportal.chart" . }}
app.kubernetes.io/name: {{ include "securityportal.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels for the api component.
*/}}
{{- define "securityportal.api.selectorLabels" -}}
app.kubernetes.io/name: {{ include "securityportal.name" . }}-api
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Selector labels for the web component.
*/}}
{{- define "securityportal.web.selectorLabels" -}}
app.kubernetes.io/name: {{ include "securityportal.name" . }}-web
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "securityportal.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "securityportal.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Resolve the database DSN Secret name.
When externalDatabase.existingSecret is set it is used directly; otherwise
the chart generates a Secret named "<release>-db-secret".
*/}}
{{- define "securityportal.dbSecretName" -}}
{{- if .Values.externalDatabase.existingSecret }}
{{- .Values.externalDatabase.existingSecret }}
{{- else if .Values.postgresql.enabled }}
{{- printf "%s-postgresql" .Release.Name }}
{{- else }}
{{- printf "%s-db-secret" (include "securityportal.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Key inside the database Secret that holds the DSN.
The Bitnami postgresql subchart uses "postgres-password" for the superuser
and exposes the connection string differently; when using the bundled subchart
we build the DSN from the subchart values instead.
*/}}
{{- define "securityportal.dbSecretKey" -}}
{{- if .Values.externalDatabase.existingSecret }}
dsn
{{- else if .Values.postgresql.enabled }}
{{- /* The bundled subchart's generated Secret holds the user password under
     this key; we build the full DSN in the api Deployment env section. */}}
password
{{- else }}
dsn
{{- end }}
{{- end }}

{{/*
Resolve the logo Secret name.
*/}}
{{- define "securityportal.logoSecretName" -}}
{{- if .Values.logo.existingSecret }}
{{- .Values.logo.existingSecret }}
{{- else }}
{{- printf "%s-logo" (include "securityportal.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Resolve the legal ConfigMap name.
*/}}
{{- define "securityportal.legalConfigMapName" -}}
{{- if .Values.legalContent.existingConfigMap }}
{{- .Values.legalContent.existingConfigMap }}
{{- else }}
{{- printf "%s-legal" (include "securityportal.fullname" .) }}
{{- end }}
{{- end }}

{{/*
True when a logo is configured (either inline data or an existing Secret).
*/}}
{{- define "securityportal.logoEnabled" -}}
{{- if or .Values.logo.data .Values.logo.existingSecret }}true{{- end }}
{{- end }}

{{/*
True when legal content is configured (either inline files or an existing ConfigMap).
*/}}
{{- define "securityportal.legalEnabled" -}}
{{- if or .Values.legalContent.existingConfigMap
         .Values.legalContent.files.impressumDe
         .Values.legalContent.files.impressumEn
         .Values.legalContent.files.datenschutzDe
         .Values.legalContent.files.datenschutzEn -}}
true
{{- end }}
{{- end }}
