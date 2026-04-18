# Adapted from https://github.com/aquasecurity/trivy-checks (KSV01011).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_authenticate_group_bind

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-1011",
	"name": "system:authenticated group access binding",
	"description": "Binding the system:authenticated group to any clusterrole or role is a security risk — any authenticated user (including Google account holders on GKE) gains the role's permissions.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-system-authenticated-group-bind",
	"languages": ["yaml"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "gke"],
}

findings contains finding if {
	some rb in k8s.role_bindings
	k8s.binding_has_system_group(rb.doc, "system:authenticated")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should not bind to system:authenticated group", [
			rb.doc.kind, k8s.resource_name(rb.doc),
		]),
		"artifact_uri": rb.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rb.line,
		"snippet": sprintf("%s/%s/subject=system:authenticated", [rb.doc.kind, k8s.resource_name(rb.doc)]),
	}
}
