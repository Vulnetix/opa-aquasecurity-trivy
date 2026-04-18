# Adapted from https://github.com/aquasecurity/trivy-checks (KSV051).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_allowing_create_role_binding_and_associate_privileged_clusterrole

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0051",
	"name": "Do not allow role binding creation and association with privileged role/clusterrole",
	"description": "Check whether role permits creating role bindings and associating to privileged role/clusterrole.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-do-not-allow-role-binding-associate-privileged-role",
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

# True if the role contains a rule that permits create on rolebindings AND
# a rule that permits bind on roles/clusterroles with wildcard resource names.
_has_privileged_binding_creation(role_doc) if {
	rules := object.get(role_doc, "rules", [])
	some i
	a := rules[i]
	"rbac.authorization.k8s.io" in object.get(a, "apiGroups", [])
	"rolebindings" in object.get(a, "resources", [])
	"create" in object.get(a, "verbs", [])

	some j
	j > i
	b := rules[j]
	"rbac.authorization.k8s.io" in object.get(b, "apiGroups", [])
	_binds_roles_or_clusterroles(b)
	"bind" in object.get(b, "verbs", [])
	"*" in object.get(b, "resourceNames", [])
}

_binds_roles_or_clusterroles(rule) if "roles" in object.get(rule, "resources", [])
_binds_roles_or_clusterroles(rule) if "clusterroles" in object.get(rule, "resources", [])

findings contains finding if {
	some r in k8s.roles
	_has_privileged_binding_creation(r.doc)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' permits creation of role binding and association with privileged role", [
			r.doc.kind, k8s.resource_name(r.doc),
		]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s", [r.doc.kind, k8s.resource_name(r.doc)]),
	}
}
