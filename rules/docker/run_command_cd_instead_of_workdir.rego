# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0013).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_run_command_cd_instead_of_workdir

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0013",
	"name": "'RUN cd ...' to change directory",
	"description": "Use WORKDIR instead of proliferating instructions like 'RUN cd ... && do-something', which are hard to read, troubleshoot, and maintain.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-use-workdir-over-cd",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "workdir", "best-practices"],
}

findings contains finding if {
	some run in docker.run_cmds
	_has_cd(run.value)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("RUN should not be used to change directory: '%s'. Use 'WORKDIR' statement instead.", [run.value]),
		"artifact_uri": run.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": run.line,
		"snippet": run.original,
	}
}

_has_cd(value) if {
	parts := regex.split(`\s*&&\s*`, value)
	some p in parts
	startswith(trim_space(p), "cd ")
}
