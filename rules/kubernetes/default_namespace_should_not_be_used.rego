# Adapted from https://github.com/aquasecurity/trivy-checks (KSV110).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_default_namespace_should_not_be_used

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0110",
	"name": "Workloads in the default namespace",
	"description": "Checks whether a workload is running in the default namespace.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-default-namespace-should-not-be-used",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-1188"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "namespace", "workload"],
}

_workload_kinds := {
	"Pod", "ReplicaSet", "ReplicationController", "Deployment",
	"StatefulSet", "DaemonSet", "CronJob", "Job",
}

findings contains finding if {
	some d in k8s.documents
	d.doc.kind in _workload_kinds
	k8s.resource_namespace(d.doc) == "default"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should set metadata.namespace to a non-default namespace", [
			d.doc.kind, k8s.resource_name(d.doc),
		]),
		"artifact_uri": d.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": d.line,
		"snippet": sprintf("%s/%s/namespace=default", [d.doc.kind, k8s.resource_name(d.doc)]),
	}
}
