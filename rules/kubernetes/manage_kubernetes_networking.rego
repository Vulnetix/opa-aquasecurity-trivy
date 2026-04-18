# Adapted from https://github.com/aquasecurity/trivy-checks (KSV056).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_manage_kubernetes_networking

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0056",
	"name": "Manage Kubernetes networking",
	"description": "The ability to control which pods get service traffic directed to them allows for interception attacks. Controlling network policy allows for bypassing lateral movement restrictions.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-manage-networking-resources",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "networking"],
}

_bad_verbs := {"create", "update", "patch", "delete", "deletecollection", "impersonate", "*"}
_resources := {"services", "endpoints", "endpointslices", "networkpolicies", "ingresses"}

findings contains finding if {
	some rr in k8s.role_rules
	some res in object.get(rr.rule, "resources", [])
	res in _resources
	some v in object.get(rr.rule, "verbs", [])
	v in _bad_verbs
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should not have write verb '%s' on networking resource '%s'", [
			rr.role.kind, k8s.resource_name(rr.role), v, res,
		]),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("%s/%s/rule.verb=%s/resource=%s", [rr.role.kind, k8s.resource_name(rr.role), v, res]),
	}
}
