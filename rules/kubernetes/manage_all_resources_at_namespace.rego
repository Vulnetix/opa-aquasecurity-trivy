# Adapted from https://github.com/aquasecurity/trivy-checks (KSV112).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_manage_all_resources_at_namespace

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0112",
	"name": "Manage all resources at the namespace",
	"description": "Full control of the resources within a namespace. In some cluster configurations, this is excessive.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-wildcard-resource-role",
	"languages": ["yaml"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "namespace"],
}

_verbs := {"create", "update", "delete", "deletecollection", "impersonate", "*", "list", "get"}

findings contains finding if {
	some rr in k8s.role_rules
	rr.role.kind == "Role"
	"*" in object.get(rr.rule, "resources", [])
	some v in object.get(rr.rule, "verbs", [])
	v in _verbs
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Role '%s' should not manage all resources (verb '%s' on '*')", [
			k8s.resource_name(rr.role), v,
		]),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("Role/%s/rule.verb=%s/resource=*", [k8s.resource_name(rr.role), v]),
	}
}
