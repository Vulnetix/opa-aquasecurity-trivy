# Adapted from https://github.com/aquasecurity/trivy-checks (KSV048).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_allowing_to_update_a_malicious_pod

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0048",
	"name": "Manage Kubernetes workloads and pods",
	"description": "Depending on the policies enforced by the admission controller, this permission ranges from the ability to steal compute by running workloads or allowing for creating workloads that escape to the node as root and escalation to cluster-admin.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-deny-create-update-malicious-pod",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "workloads"],
}

_workloads := {
	"pods", "deployments", "jobs", "cronjobs", "statefulsets",
	"daemonsets", "replicasets", "replicationcontrollers",
}

_change_verbs := {"create", "update", "patch", "delete", "deletecollection", "impersonate", "*"}

findings contains finding if {
	some rr in k8s.role_rules
	some res in object.get(rr.rule, "resources", [])
	res in _workloads
	some v in object.get(rr.rule, "verbs", [])
	v in _change_verbs
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should not have access to workload resource '%s' for verb '%s'", [
			rr.role.kind, k8s.resource_name(rr.role), res, v,
		]),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("%s/%s/rule.verb=%s/resource=%s", [rr.role.kind, k8s.resource_name(rr.role), v, res]),
	}
}
