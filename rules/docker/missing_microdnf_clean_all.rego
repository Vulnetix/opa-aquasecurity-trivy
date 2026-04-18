# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0027).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_missing_microdnf_clean_all

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0027",
	"name": "'microdnf clean all' missing",
	"description": "Cached package data should be cleaned after installation to reduce image size.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-purge-microdnf-package-cache",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "microdnf", "image-size"],
}

_install_regex := `(microdnf install)|(microdnf reinstall)`

_microdnf_regex := `(microdnf install)|(microdnf reinstall)|(microdnf clean all)`

findings contains finding if {
	some run in docker.run_cmds
	regex.match(_install_regex, run.value)
	not _ends_with_clean_all(run.value)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'microdnf clean all' is missed: %s", [run.value]),
		"artifact_uri": run.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": run.line,
		"snippet": run.original,
	}
}

_ends_with_clean_all(value) if {
	matches := regex.find_n(_microdnf_regex, value, -1)
	count(matches) > 0
	matches[count(matches) - 1] == "microdnf clean all"
}
