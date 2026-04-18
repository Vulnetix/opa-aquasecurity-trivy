# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0024).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_run_apt_get_dist_upgrade

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0024",
	"name": "'apt-get dist-upgrade' used",
	"description": "'apt-get dist-upgrade' upgrades a major version so it doesn't make more sense in Dockerfile.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-no-dist-upgrade",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "apt", "deprecated"],
}

findings contains finding if {
	some run in docker.run_cmds
	regex.match(`apt-get .* dist-upgrade`, run.value)
	finding := {
		"rule_id": metadata.id,
		"message": "'apt-get dist-upgrade' should not be used in Dockerfile",
		"artifact_uri": run.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": run.line,
		"snippet": run.original,
	}
}
