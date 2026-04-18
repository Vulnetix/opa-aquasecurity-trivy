# Adapted from https://github.com/aquasecurity/trivy-checks (KSV043).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_impersonate_privileged_groups

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0043",
	"name": "Do not allow impersonation of privileged groups",
	"description": "Check whether role permits impersonating privileged groups.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-impersonate-privileged-groups",
	"languages": ["yaml"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "impersonation"],
}

findings contains finding if {
	some rr in k8s.role_rules
	"*" in object.get(rr.rule, "apiGroups", [])
	"groups" in object.get(rr.rule, "resources", [])
	"impersonate" in object.get(rr.rule, "verbs", [])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' permits impersonation of privileged groups", [
			rr.role.kind, k8s.resource_name(rr.role),
		]),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("%s/%s/rule=impersonate:groups", [rr.role.kind, k8s.resource_name(rr.role)]),
	}
}
