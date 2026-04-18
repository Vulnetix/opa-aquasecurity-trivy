# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0015).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_yum_clean_all_missing

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0015",
	"name": "'yum clean all' missing",
	"description": "You should use 'yum clean all' after using a 'yum install' command to clean package cached data and reduce image size.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-purge-yum-package-cache",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "yum", "image-size"],
}

findings contains finding if {
	some run in docker.run_cmds
	install_positions := _yum_install_positions(run.value)
	count(install_positions) > 0
	not _followed_by_clean_all(run.value, install_positions)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'yum clean all' is missed: %s", [run.value]),
		"artifact_uri": run.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": run.line,
		"snippet": run.original,
	}
}

_yum_install_positions(value) := [idx |
	subs := docker.split_run(value)
	some idx, sub in subs
	regex.match(`^\s*yum(\s+-{1,2}[a-zA-Z]+)*\s+install(\s|$)`, sub)
]

_followed_by_clean_all(value, install_positions) if {
	subs := docker.split_run(value)
	clean_all_positions := [idx |
		some idx, sub in subs
		contains(sub, "yum")
		contains(sub, "clean")
		contains(sub, "all")
	]
	count(clean_all_positions) > 0
	max_install := install_positions[count(install_positions) - 1]
	max_clean := clean_all_positions[count(clean_all_positions) - 1]
	max_install < max_clean
}
