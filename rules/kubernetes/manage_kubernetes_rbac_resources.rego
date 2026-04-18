# Adapted from https://github.com/aquasecurity/trivy-checks (KSV050).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_manage_kubernetes_rbac_resources

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0050",
	"name": "Do not allow privilege escalation via RBAC resources",
	"description": "Check whether role permits escalate, bind, or impersonate on roles/rolebindings, which can lead to privilege escalation.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-privilege-escalation-rbac",
	"languages": ["yaml"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "privilege-escalation"],
}

_critical_verbs := {"escalate", "bind", "impersonate", "*"}
_critical_resources := {"roles", "rolebindings"}

findings contains finding if {
	some rr in k8s.role_rules
	some res in object.get(rr.rule, "resources", [])
	res in _critical_resources
	some v in object.get(rr.rule, "verbs", [])
	v in _critical_verbs
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should not have verb '%s' on RBAC resource '%s' (privilege escalation risk)", [
			rr.role.kind, k8s.resource_name(rr.role), v, res,
		]),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("%s/%s/rule.verb=%s/resource=%s", [rr.role.kind, k8s.resource_name(rr.role), v, res]),
	}
}
