# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0123).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_masters_group_bind

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0123",
	"name": "system:masters group access binding",
	"description": "Binding to system:masters group to any clusterrole or role is a security risk.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-system-masters-group-bind",
	"languages": ["yaml"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac"],
}

findings contains finding if {
	some b in k8s.role_bindings
	k8s.binding_has_system_group(b.doc, "system:masters")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' binds the 'system:masters' group",
			[b.doc.kind, k8s.resource_name(b.doc)],
		),
		"artifact_uri": b.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": b.line,
		"snippet": sprintf("%s/%s", [b.doc.kind, k8s.resource_name(b.doc)]),
	}
}
