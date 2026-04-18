# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0008).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_unix_ports_out_of_range

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0008",
	"name": "Exposed port out of range",
	"description": "UNIX ports outside the range 0-65535 are exposed.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-port-out-of-range",
	"languages": ["dockerfile"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "network"],
}

findings contains finding if {
	some exp in docker.expose_cmds
	some token in regex.split(`\s+`, trim_space(exp.value))
	token != ""
	port_str := split(token, "/")[0]
	regex.match(`^\d+$`, port_str)
	port := to_number(port_str)
	port > 65535
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'EXPOSE' contains port which is out of range [0, 65535]: %d", [port]),
		"artifact_uri": exp.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": exp.line,
		"snippet": exp.original,
	}
}
