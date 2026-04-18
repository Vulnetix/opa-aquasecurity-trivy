# Adapted from https://github.com/aquasecurity/trivy-checks (KSV009).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_host_network

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0009",
	"name": "Access to host network",
	"description": "Sharing the host's network namespace permits processes in the pod to communicate with processes bound to the host's loopback adapter.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-host-network",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-668"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "host", "network"],
}

findings contains finding if {
	some r in k8s.resources_with_pod_templates
	object.get(r.pod_template.spec, "hostNetwork", false) == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should not set 'spec.template.spec.hostNetwork' to true", [
			r.resource.kind, k8s.resource_name(r.resource),
		]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s/hostNetwork=true", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}
