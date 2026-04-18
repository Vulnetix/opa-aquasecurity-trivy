# Adapted from https://github.com/aquasecurity/trivy-checks (KSV049).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_manage_configmaps

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0049",
	"name": "Manage configmaps",
	"description": "Some workloads leverage configmaps to store sensitive data or configuration parameters that affect runtime behavior that can be modified by an attacker or combined with another issue to potentially lead to compromise.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-manage-configmaps",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "configmap"],
}

_bad_verbs := {"create", "update", "patch", "delete", "deletecollection", "impersonate", "*"}

findings contains finding if {
	some rr in k8s.role_rules
	"configmaps" in object.get(rr.rule, "resources", [])
	some v in object.get(rr.rule, "verbs", [])
	v in _bad_verbs
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should not have write verb '%s' on 'configmaps'", [
			rr.role.kind, k8s.resource_name(rr.role), v,
		]),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("%s/%s/rule.verb=%s/configmaps", [rr.role.kind, k8s.resource_name(rr.role), v]),
	}
}
