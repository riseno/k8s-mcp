{{- define "k8s-mcp.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "k8s-mcp.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "k8s-mcp.labels" -}}
{{ include "k8s-mcp.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "k8s-mcp.serviceAccountName" -}}
{{- default (include "k8s-mcp.fullname" .) .Values.serviceAccount.name -}}
{{- end -}}

{{/* Host values the server accepts: its Service names, loopback (port-forward) and extras. */}}
{{- define "k8s-mcp.allowedHosts" -}}
{{- $name := include "k8s-mcp.fullname" . -}}
{{- $ns := .Release.Namespace -}}
{{- $hosts := list $name (printf "%s.%s" $name $ns) (printf "%s.%s.svc" $name $ns) (printf "%s.%s.svc.%s" $name $ns .Values.clusterDomain) "localhost" "127.0.0.1" -}}
{{- concat $hosts .Values.allowedHosts | uniq | join "," -}}
{{- end -}}
