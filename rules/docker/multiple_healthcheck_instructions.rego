# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0023).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_multiple_healthcheck_instructions

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0023",
	"name": "Multiple HEALTHCHECK defined",
	"description": "Providing more than one HEALTHCHECK instruction per stage is confusing and error-prone.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-only-one-healthcheck",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "healthcheck", "best-practices"],
}

findings contains finding if {
	some stage in docker.stages
	hcs := [i | some i in stage.instructions; i.cmd == "healthcheck"]
	count(hcs) > 1
	second := hcs[1]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("There are %d duplicate HEALTHCHECK instructions in the stage", [count(hcs)]),
		"artifact_uri": stage.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": second.line,
		"snippet": second.original,
	}
}
