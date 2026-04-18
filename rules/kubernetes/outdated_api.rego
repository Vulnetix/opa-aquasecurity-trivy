# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0107).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: only a curated subset of the most common removed/deprecated
# Kubernetes APIs is encoded here.

package vulnetix.rules.trivy_k8s_outdated_api

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0107",
	"name": "The deprecated 'apiVersion' and 'kind' should not be used",
	"description": "The specified 'apiVersion' and 'kind' are deprecated and are planned to be removed.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-evaluate-k8s-deprecated-removed-apis",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-477"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "deprecation", "api"],
}

# Minimal curated table of deprecated/removed API + kind pairs.
# Each entry maps "apiVersion/Kind" to a short replacement note.
_removed_apis := {
	"extensions/v1beta1/Deployment": "apps/v1 Deployment",
	"extensions/v1beta1/DaemonSet": "apps/v1 DaemonSet",
	"extensions/v1beta1/ReplicaSet": "apps/v1 ReplicaSet",
	"extensions/v1beta1/Ingress": "networking.k8s.io/v1 Ingress",
	"extensions/v1beta1/NetworkPolicy": "networking.k8s.io/v1 NetworkPolicy",
	"apps/v1beta1/Deployment": "apps/v1 Deployment",
	"apps/v1beta1/DaemonSet": "apps/v1 DaemonSet",
	"apps/v1beta1/ReplicaSet": "apps/v1 ReplicaSet",
	"apps/v1beta1/StatefulSet": "apps/v1 StatefulSet",
	"apps/v1beta2/Deployment": "apps/v1 Deployment",
	"apps/v1beta2/DaemonSet": "apps/v1 DaemonSet",
	"apps/v1beta2/ReplicaSet": "apps/v1 ReplicaSet",
	"apps/v1beta2/StatefulSet": "apps/v1 StatefulSet",
	"batch/v1beta1/CronJob": "batch/v1 CronJob",
	"policy/v1beta1/PodSecurityPolicy": "removed in v1.25 (use PodSecurity admission)",
	"policy/v1beta1/PodDisruptionBudget": "policy/v1 PodDisruptionBudget",
	"networking.k8s.io/v1beta1/Ingress": "networking.k8s.io/v1 Ingress",
	"networking.k8s.io/v1beta1/IngressClass": "networking.k8s.io/v1 IngressClass",
	"rbac.authorization.k8s.io/v1beta1/Role": "rbac.authorization.k8s.io/v1 Role",
	"rbac.authorization.k8s.io/v1beta1/RoleBinding": "rbac.authorization.k8s.io/v1 RoleBinding",
	"rbac.authorization.k8s.io/v1beta1/ClusterRole": "rbac.authorization.k8s.io/v1 ClusterRole",
	"rbac.authorization.k8s.io/v1beta1/ClusterRoleBinding": "rbac.authorization.k8s.io/v1 ClusterRoleBinding",
	"admissionregistration.k8s.io/v1beta1/MutatingWebhookConfiguration": "admissionregistration.k8s.io/v1 MutatingWebhookConfiguration",
	"admissionregistration.k8s.io/v1beta1/ValidatingWebhookConfiguration": "admissionregistration.k8s.io/v1 ValidatingWebhookConfiguration",
}

findings contains finding if {
	some d in k8s.documents
	key := sprintf("%s/%s", [d.doc.apiVersion, d.doc.kind])
	replacement := _removed_apis[key]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"apiVersion '%s' kind '%s' is deprecated or removed; migrate to %s",
			[d.doc.apiVersion, d.doc.kind, replacement],
		),
		"artifact_uri": d.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": d.line,
		"snippet": sprintf("%s/%s", [d.doc.apiVersion, d.doc.kind]),
	}
}
