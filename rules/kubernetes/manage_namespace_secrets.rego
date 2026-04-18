# Adapted from https://github.com/aquasecurity/trivy-checks (KSV113).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_manage_namespace_secrets

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0113",
	"name": "Manage namespace secrets",
	"description": "Viewing secrets at the namespace scope can lead to escalation if another service account in that namespace has a higher privileged rolebinding or clusterrolebinding bound.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-manage-ns-secrets",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "secrets"],
}

_any_verbs := {"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "impersonate", "*"}

findings contains finding if {
	some rr in k8s.role_rules
	rr.role.kind == "Role"
	"secrets" in object.get(rr.rule, "resources", [])
	some v in object.get(rr.rule, "verbs", [])
	v in _any_verbs
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Role '%s' should not grant verb '%s' on secrets in namespace '%s'", [
			k8s.resource_name(rr.role), v, k8s.resource_namespace(rr.role),
		]),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("Role/%s/rule.verb=%s/resource=secrets", [k8s.resource_name(rr.role), v]),
	}
}
