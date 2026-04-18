# Adapted from https://github.com/aquasecurity/trivy-checks (KSV044).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_any_any

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0044",
	"name": "No wildcard verb and resource roles",
	"description": "Check whether role permits wildcard verb on wildcard resource.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-wildcard-verb-resource-role",
	"languages": ["yaml"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "wildcard"],
}

findings contains finding if {
	some rr in k8s.role_rules
	k8s.rule_has_wildcard_apigroup(rr.rule)
	k8s.rule_has_wildcard_resource(rr.rule)
	k8s.rule_has_wildcard_verb(rr.rule)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' permits wildcard verb on wildcard resource", [
			rr.role.kind, k8s.resource_name(rr.role),
		]),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("%s/%s/rule=*:*:*", [rr.role.kind, k8s.resource_name(rr.role)]),
	}
}
