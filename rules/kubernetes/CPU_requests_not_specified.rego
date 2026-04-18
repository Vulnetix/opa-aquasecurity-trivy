# Adapted from https://github.com/aquasecurity/trivy-checks (KSV015).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_cpu_requests_not_specified

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0015",
	"name": "CPU requests not specified",
	"description": "When containers have resource requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-unspecified-cpu-requests",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-770"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "resource-requests", "cpu"],
}

findings contains finding if {
	some c in k8s.all_containers
	requests := object.get(object.get(c.container, "resources", {}), "requests", {})
	not object.get(requests, "cpu", false)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Container '%s' of %s '%s' should set 'resources.requests.cpu'", [
			c.container.name, c.resource.kind, k8s.resource_name(c.resource),
		]),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
