# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0029).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_apt_get_missing_no_install_recommends

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0029",
	"name": "'apt-get' missing '--no-install-recommends'",
	"description": "'apt-get' install should use '--no-install-recommends' to minimize image size.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-use-apt-no-install-recommends",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "apt", "best-practices", "image-size"],
}

findings contains finding if {
	some run in docker.run_cmds
	_apt_get_install_without_no_install_recommends(run.value)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'--no-install-recommends' flag is missed: '%s'", [run.value]),
		"artifact_uri": run.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": run.line,
		"snippet": run.original,
	}
}

_apt_get_install_without_no_install_recommends(value) if {
	regex.match(`apt-get(\s+-{1,2}[a-zA-Z]+)*\s+install`, value)
	not contains(value, "--no-install-recommends")
}
