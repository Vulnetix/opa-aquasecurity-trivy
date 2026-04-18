# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0016).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_multiple_cmd_instructions_listed

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0016",
	"name": "Multiple CMD instructions listed",
	"description": "There can only be one CMD instruction in a Dockerfile. If you list more than one CMD then only the last CMD will take effect.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-only-one-cmd",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "cmd", "best-practices"],
}

findings contains finding if {
	some stage in docker.stages
	cmds := [i | some i in stage.instructions; i.cmd == "cmd"]
	count(cmds) > 1
	second := cmds[1]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("There are %d duplicate CMD instructions", [count(cmds)]),
		"artifact_uri": stage.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": second.line,
		"snippet": second.original,
	}
}
