# Adapted from https://github.com/aquasecurity/trivy-checks (KSV055).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_allowing_users_rolebinding_add_other_users_rolebindings

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0055",
	"name": "Do not allow users in a rolebinding to add other users to their rolebindings",
	"description": "Check whether role permits allowing users in a rolebinding to add other users to their rolebindings.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-view-all-secrets",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "privilege-escalation"],
}

findings contains finding if {
	some rr in k8s.role_rules
	"*" in object.get(rr.rule, "apiGroups", [])
	"rolebindings" in object.get(rr.rule, "resources", [])
	verbs := object.get(rr.rule, "verbs", [])
	"get" in verbs
	"patch" in verbs
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' permits users in a rolebinding to add other users to their rolebindings", [
			rr.role.kind, k8s.resource_name(rr.role),
		]),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("%s/%s", [rr.role.kind, k8s.resource_name(rr.role)]),
	}
}
