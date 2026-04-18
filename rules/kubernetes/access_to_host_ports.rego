# Adapted from https://github.com/aquasecurity/trivy-checks (KSV024).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_access_to_host_ports

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0024",
	"name": "Access to host ports",
	"description": "According to pod security standard 'Host Ports', hostPorts should be disallowed, or at minimum restricted to a known list.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-host-port-access",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "host-port", "network"],
}

findings contains finding if {
	some c in k8s.all_containers
	some port in object.get(c.container, "ports", [])
	hp := object.get(port, "hostPort", 0)
	hp != 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Container '%s' of %s '%s' should not set host ports, 'ports[*].hostPort=%d'", [
			c.container.name, c.resource.kind, k8s.resource_name(c.resource), hp,
		]),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s/hostPort=%d", [c.resource.kind, k8s.resource_name(c.resource), c.container.name, hp]),
	}
}
