# Adapted from https://github.com/aquasecurity/trivy-checks (KSV041).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_manage_secrets

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0041",
	"name": "Manage secrets",
	"description": "Viewing secrets at the cluster-scope is akin to cluster-admin in most clusters.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-manage-secrets",
	"languages": ["yaml"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "secrets", "clusterrole"],
}

_any_verbs := {"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "impersonate", "*"}

findings contains finding if {
	some rr in k8s.role_rules
	rr.role.kind == "ClusterRole"
	"secrets" in object.get(rr.rule, "resources", [])
	some v in object.get(rr.rule, "verbs", [])
	v in _any_verbs
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ClusterRole '%s' should not grant verb '%s' on cluster-scoped secrets", [
			k8s.resource_name(rr.role), v,
		]),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("ClusterRole/%s/rule.verb=%s/resource=secrets", [k8s.resource_name(rr.role), v]),
	}
}
