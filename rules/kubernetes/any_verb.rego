# Adapted from https://github.com/aquasecurity/trivy-checks (KSV045).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_any_verb

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0045",
	"name": "No wildcard verb roles",
	"description": "Check whether role permits wildcard verb on specific sensitive resources.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-wildcard-verb-role",
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

_sensitive := {
	"secrets", "pods", "deployments", "daemonsets", "statefulsets",
	"replicationcontrollers", "replicasets", "cronjobs", "jobs",
	"roles", "clusterroles", "rolebindings", "clusterrolebindings",
	"users", "groups",
}

findings contains finding if {
	some rr in k8s.role_rules
	k8s.rule_has_wildcard_verb(rr.rule)
	some res in object.get(rr.rule, "resources", [])
	res in _sensitive
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' permits wildcard verb on sensitive resource '%s'", [
			rr.role.kind, k8s.resource_name(rr.role), res,
		]),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("%s/%s/rule=*:%s", [rr.role.kind, k8s.resource_name(rr.role), res]),
	}
}
