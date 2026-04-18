# Adapted from https://github.com/aquasecurity/trivy-checks (KSV046).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_manage_all_resources

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0046",
	"name": "Manage all resources",
	"description": "Full control of the cluster resources, and therefore also root on all nodes where workloads can run and has access to all pods, secrets, and data.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-wildcard-resource-clusterrole",
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

_verbs := {"create", "update", "delete", "deletecollection", "impersonate", "*", "list", "get"}

findings contains finding if {
	some rr in k8s.role_rules
	rr.role.kind == "ClusterRole"
	"*" in object.get(rr.rule, "resources", [])
	some v in object.get(rr.rule, "verbs", [])
	v in _verbs
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ClusterRole '%s' should not manage all resources (verb '%s' on '*')", [
			k8s.resource_name(rr.role), v,
		]),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("ClusterRole/%s/rule.verb=%s/resource=*", [k8s.resource_name(rr.role), v]),
	}
}
