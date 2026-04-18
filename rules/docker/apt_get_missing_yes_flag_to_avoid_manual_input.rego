# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0021).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_apt_get_missing_yes_flag_to_avoid_manual_input

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0021",
	"name": "'apt-get' missing '-y' to avoid manual input",
	"description": "'apt-get' calls should use the flag '-y' to avoid manual user input.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-use-apt-auto-confirm",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "apt", "best-practices"],
}

findings contains finding if {
	some run in docker.run_cmds
	_apt_get_install_without_yes(run.value)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'-y' flag is missed: '%s'", [run.value]),
		"artifact_uri": run.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": run.line,
		"snippet": run.original,
	}
}

_apt_get_install_without_yes(value) if {
	regex.match(`apt-get(\s+-{1,2}[a-zA-Z]+)*\s+install`, value)
	not _has_yes_flag(value)
}

_has_yes_flag(value) if regex.match(`(^|\s)-([a-xzA-XZ]*y[a-xzA-XZ]*)(\s|$)`, value)

_has_yes_flag(value) if contains(value, "--yes")

_has_yes_flag(value) if contains(value, "--assume-yes")
