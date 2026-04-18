# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0037).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_protect_core_components_namespace

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0037",
	"name": "User resources should not be placed in kube-system namespace",
	"description": "Ensure that user resources are not placed in kube-system namespace.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-user-resources-in-system-namespace",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-732"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "namespaces"],
}

_core_labels := {"kube-apiserver", "etcd", "kube-controller-manager", "kube-scheduler"}

_is_core_component(doc) if {
	labels := object.get(object.get(doc, "metadata", {}), "labels", {})
	labels.tier == "control-plane"
	labels.component in _core_labels
	object.get(k8s.pod_spec(doc), "priorityClassName", "") == "system-node-critical"
}

findings contains finding if {
	some d in k8s.namespaced_resources
	k8s.resource_namespace(d.doc) == "kube-system"
	not _is_core_component(d.doc)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' is placed in the 'kube-system' namespace",
			[d.doc.kind, k8s.resource_name(d.doc)],
		),
		"artifact_uri": d.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": d.line,
		"snippet": sprintf("%s/%s", [d.doc.kind, k8s.resource_name(d.doc)]),
	}
}
