# Adapted from https://github.com/aquasecurity/trivy-checks (KSV052).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_allowing_create_role_clusterrolebinding_and_associate_privileged_clusterrole

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0052",
	"name": "Do not allow role to create ClusterRoleBindings and association with privileged role",
	"description": "Check whether role permits creating ClusterRoleBindings and association with privileged cluster role.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-allow-role-clusterrolebindings-associate-privileged-cluster-role",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "privilege-escalation"],
}

_has_crb_creation_with_clusterrole_bind(role_doc) if {
	rules := object.get(role_doc, "rules", [])
	some i
	a := rules[i]
	"rbac.authorization.k8s.io" in object.get(a, "apiGroups", [])
	"clusterrolebindings" in object.get(a, "resources", [])
	"create" in object.get(a, "verbs", [])

	some j
	j > i
	b := rules[j]
	"clusterroles" in object.get(b, "resources", [])
	"bind" in object.get(b, "verbs", [])
	"*" in object.get(b, "resourceNames", [])
}

findings contains finding if {
	some r in k8s.roles
	_has_crb_creation_with_clusterrole_bind(r.doc)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' permits creation of clusterrolebinding and association with privileged clusterrole", [
			r.doc.kind, k8s.resource_name(r.doc),
		]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s", [r.doc.kind, k8s.resource_name(r.doc)]),
	}
}
