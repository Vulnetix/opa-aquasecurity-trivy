# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0020).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_missing_zypper_clean

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0020",
	"name": "'zypper clean' missing",
	"description": "The layer and image size should be reduced by deleting unneeded caches after running zypper.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-purge-zipper-cache",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "zypper", "image-size"],
}

_install_regex := `(zypper in)|(zypper remove)|(zypper rm)|(zypper source-install)|(zypper si)|(zypper patch)|(zypper(\s+-{1,2}[a-zA-Z]+)*\s+install)`

_zypper_regex := `(zypper in)|(zypper remove)|(zypper rm)|(zypper source-install)|(zypper si)|(zypper patch)|(zypper(\s+-{1,2}[a-zA-Z]+)*\s+install)|(zypper clean)|(zypper cc)`

findings contains finding if {
	some run in docker.run_cmds
	regex.match(_install_regex, run.value)
	not _ends_with_clean(run.value)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'zypper clean' is missed: '%s'", [run.value]),
		"artifact_uri": run.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": run.line,
		"snippet": run.original,
	}
}

_ends_with_clean(value) if {
	matches := regex.find_n(_zypper_regex, value, -1)
	count(matches) > 0
	last := matches[count(matches) - 1]
	_is_clean(last)
}

_is_clean(cmd) if cmd == "zypper clean"

_is_clean(cmd) if cmd == "zypper cc"
