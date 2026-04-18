# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0007).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_multiple_entrypoint_instructions_listed

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0007",
	"name": "Multiple ENTRYPOINT instructions listed",
	"description": "There can only be one ENTRYPOINT instruction in a Dockerfile. Only the last ENTRYPOINT instruction in the Dockerfile will have an effect.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-only-one-entrypoint",
	"languages": ["dockerfile"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "entrypoint", "best-practices"],
}

findings contains finding if {
	some stage in docker.stages
	entries := [i | some i in stage.instructions; i.cmd == "entrypoint"]
	count(entries) > 1
	second := entries[1]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("There are %d duplicate ENTRYPOINT instructions", [count(entries)]),
		"artifact_uri": stage.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": second.line,
		"snippet": second.original,
	}
}
