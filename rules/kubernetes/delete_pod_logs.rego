# Adapted from https://github.com/aquasecurity/trivy-checks (KSV042).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_delete_pod_logs

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0042",
	"name": "Delete pod logs",
	"description": "Used to cover attacker's tracks, but most clusters ship logs quickly off-cluster.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-delete-pod-logs",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-778"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "audit"],
}

_bad_verbs := {"delete", "deletecollection", "*"}

findings contains finding if {
	some rr in k8s.role_rules
	"pods/log" in object.get(rr.rule, "resources", [])
	some v in object.get(rr.rule, "verbs", [])
	v in _bad_verbs
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should not have verb '%s' on 'pods/log'", [
			rr.role.kind, k8s.resource_name(rr.role), v,
		]),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("%s/%s/rule.verb=%s", [rr.role.kind, k8s.resource_name(rr.role), v]),
	}
}
