# Adapted from https://github.com/aquasecurity/trivy-checks (KSV111).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_cluster_admin_role_is_only_used_where_required

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0111",
	"name": "User with admin access",
	"description": "Either cluster-admin or those granted powerful permissions.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-cluster-admin0-role-only-used-where-required",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "cluster-admin"],
}

_powerful := {"cluster-admin", "admin", "edit"}

findings contains finding if {
	some rb in k8s.role_bindings
	role_ref := object.get(rb.doc, "roleRef", {})
	name := object.get(role_ref, "name", "")
	name in _powerful
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should not bind to powerful role '%s'", [
			rb.doc.kind, k8s.resource_name(rb.doc), name,
		]),
		"artifact_uri": rb.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rb.line,
		"snippet": sprintf("%s/%s/roleRef=%s", [rb.doc.kind, k8s.resource_name(rb.doc), name]),
	}
}
