# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0004).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_port22

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0004",
	"name": "Port 22 exposed",
	"description": "Exposing port 22 might allow users to SSH into the container.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-no-ssh-port",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "ssh", "network"],
}

_denied := {"22", "22/tcp", "22/udp"}

findings contains finding if {
	some exp in docker.expose_cmds
	some token in regex.split(`\s+`, trim_space(exp.value))
	token in _denied
	finding := {
		"rule_id": metadata.id,
		"message": "Port 22 should not be exposed in Dockerfile",
		"artifact_uri": exp.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": exp.line,
		"snippet": exp.original,
	}
}
