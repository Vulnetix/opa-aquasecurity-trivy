# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0010).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_run_using_sudo

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0010",
	"name": "RUN using 'sudo'",
	"description": "Avoid using 'RUN' with 'sudo' commands, as it can lead to unpredictable behavior.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-no-sudo-run",
	"languages": ["dockerfile"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "sudo", "least-privilege"],
}

findings contains finding if {
	some run in docker.run_cmds
	_has_sudo(run.value)
	finding := {
		"rule_id": metadata.id,
		"message": "Using 'sudo' in Dockerfile should be avoided",
		"artifact_uri": run.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": run.line,
		"snippet": run.original,
	}
}

_has_sudo(value) if {
	parts := split(value, "&&")
	some p in parts
	regex.match(`^\s*sudo(\s|$)`, p)
}
