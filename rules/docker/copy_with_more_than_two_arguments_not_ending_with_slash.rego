# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0011).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_copy_with_more_than_two_arguments_not_ending_with_slash

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0011",
	"name": "COPY with more than two arguments not ending with slash",
	"description": "When a COPY command has more than two arguments, the last one should end with a slash.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-use-slash-for-copy-args",
	"languages": ["dockerfile"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "copy", "best-practices"],
}

findings contains finding if {
	some cp in docker.copy_cmds
	args := _copy_args(cp.value)
	count(args) > 2
	last_arg := args[count(args) - 1]
	not endswith(last_arg, "/")
	not endswith(last_arg, `/"`)
	not endswith(last_arg, "/'")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Slash is expected at the end of COPY command argument '%s'", [last_arg]),
		"artifact_uri": cp.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": cp.line,
		"snippet": cp.original,
	}
}

# Return COPY args with flags (e.g. --chown=...) removed.
_copy_args(value) := out if {
	docker.is_json_array(value)
	parsed := docker.json_exec_args(value)
	out := [a | some a in parsed; not startswith(a, "--")]
} else := out if {
	parts := regex.split(`\s+`, trim_space(value))
	out := [a | some a in parts; not startswith(a, "--"); a != ""]
}
