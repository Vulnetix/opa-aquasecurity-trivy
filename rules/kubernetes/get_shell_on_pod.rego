# Adapted from https://github.com/aquasecurity/trivy-checks (KSV053).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_get_shell_on_pod

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0053",
	"name": "Exec into Pods",
	"description": "The ability to exec into a container with privileged access to the host or with an attached SA with higher RBAC permissions is a common escalation path to cluster-admin.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-getting-shell-pods",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "pod-exec"],
}

_bad_verbs := {"create", "update", "patch", "delete", "deletecollection", "impersonate", "*"}

findings contains finding if {
	some rr in k8s.role_rules
	"pods/exec" in object.get(rr.rule, "resources", [])
	some v in object.get(rr.rule, "verbs", [])
	v in _bad_verbs
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should not have verb '%s' on 'pods/exec'", [
			rr.role.kind, k8s.resource_name(rr.role), v,
		]),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("%s/%s/rule.verb=%s/pods/exec", [rr.role.kind, k8s.resource_name(rr.role), v]),
	}
}
