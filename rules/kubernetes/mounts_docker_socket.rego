# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0006).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_mounts_docker_socket

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0006",
	"name": "hostPath volume mounted with docker.sock",
	"description": "Mounting docker.sock from the host can give the container full root access to the host.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-docker-sock-mount",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-732"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "docker", "privilege"],
}

findings contains finding if {
	some r in k8s.resources_with_pod_templates
	some vol in object.get(r.pod_template.spec, "volumes", [])
	hp := object.get(vol, "hostPath", {})
	object.get(hp, "path", "") == "/var/run/docker.sock"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' mounts '/var/run/docker.sock' via hostPath volume '%s'",
			[r.resource.kind, k8s.resource_name(r.resource), object.get(vol, "name", "<unnamed>")],
		),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}
