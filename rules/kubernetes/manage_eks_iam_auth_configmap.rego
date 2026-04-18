# Adapted from https://github.com/aquasecurity/trivy-checks (KSV115).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_manage_eks_iam_auth_configmap

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0115",
	"name": "Manage EKS IAM Auth ConfigMap",
	"description": "Ability to add AWS IAM to RBAC bindings via special EKS configmap.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-eks-iam-configmap",
	"languages": ["yaml"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "eks", "aws"],
}

_bad_verbs := {"create", "update", "patch", "delete", "deletecollection", "impersonate", "*"}

findings contains finding if {
	some rr in k8s.role_rules
	"configmaps" in object.get(rr.rule, "resources", [])
	"aws-auth" in object.get(rr.rule, "resourceNames", [])
	some v in object.get(rr.rule, "verbs", [])
	v in _bad_verbs
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should not have write verb '%s' on configmap 'aws-auth'", [
			rr.role.kind, k8s.resource_name(rr.role), v,
		]),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("%s/%s/rule.verb=%s/configmap=aws-auth", [rr.role.kind, k8s.resource_name(rr.role), v]),
	}
}
