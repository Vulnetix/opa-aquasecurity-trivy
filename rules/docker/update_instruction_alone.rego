# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0017).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_update_instruction_alone

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0017",
	"name": "'RUN <package-manager> update' instruction alone",
	"description": "The instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-no-orphan-package-update",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "package-manager", "best-practices"],
}

_update_cmds := {"update", "up"}

_install_cmds := {"upgrade", "install", "source-install", "reinstall", "groupinstall", "localinstall", "add"}

_package_managers := [
	{"apt-get", "apt"},
	{"yum"},
	{"apk"},
	{"dnf"},
	{"zypper"},
]

findings contains finding if {
	some run in docker.run_cmds
	some pm in _package_managers
	update_positions := _positions(run.value, pm, _update_cmds)
	count(update_positions) > 0
	install_positions := _positions(run.value, pm, _install_cmds)
	not _any_update_before_install(update_positions, install_positions)
	finding := {
		"rule_id": metadata.id,
		"message": "The instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement.",
		"artifact_uri": run.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": run.line,
		"snippet": run.original,
	}
}

# Returns index list (in split order) for sub-commands matching
# `<package_manager_name>\s+<sub_cmd>` with optional flags between.
_positions(value, pms, subs) := out if {
	subcmds := docker.split_run(value)
	out := [idx |
		some idx, sub in subcmds
		trimmed := trim_space(sub)
		some pm in pms
		some subcmd in subs
		regex.match(sprintf(`^%s(\s+-{1,2}[a-zA-Z]+)*\s+%s(\s|$)`, [pm, subcmd]), trimmed)
	]
}

_any_update_before_install(update_positions, install_positions) if {
	some u in update_positions
	some i in install_positions
	u < i
}
