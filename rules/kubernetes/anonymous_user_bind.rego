# Adapted from https://github.com/aquasecurity/trivy-checks (KSV122).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_anonymous_user_bind

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0122",
	"name": "Anonymous user access binding",
	"description": "Binding to anonymous user to any clusterrole or role is a security risk.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-anonymous-user-bind",
	"languages": ["yaml"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "anonymous"],
}

_anon := {"system:unauthenticated", "system:anonymous"}

findings contains finding if {
	some rb in k8s.role_bindings
	some group in _anon
	k8s.binding_has_system_group(rb.doc, group)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should not bind to anonymous group '%s'", [
			rb.doc.kind, k8s.resource_name(rb.doc), group,
		]),
		"artifact_uri": rb.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rb.line,
		"snippet": sprintf("%s/%s/subject=%s", [rb.doc.kind, k8s.resource_name(rb.doc), group]),
	}
}

findings contains finding if {
	some rb in k8s.role_bindings
	some sub in object.get(rb.doc, "subjects", [])
	sub.kind == "User"
	sub.name in _anon
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should not bind to anonymous user '%s'", [
			rb.doc.kind, k8s.resource_name(rb.doc), sub.name,
		]),
		"artifact_uri": rb.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rb.line,
		"snippet": sprintf("%s/%s/subject=%s", [rb.doc.kind, k8s.resource_name(rb.doc), sub.name]),
	}
}
