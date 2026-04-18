# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0026).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_no_healthcheck_instruction

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0026",
	"name": "No HEALTHCHECK defined",
	"description": "You should add HEALTHCHECK instruction in your docker container images to perform the health check on running containers.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-no-healthcheck",
	"languages": ["dockerfile"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "healthcheck", "best-practices"],
}

findings contains finding if {
	some f in docker.dockerfiles
	hcs := [i | some i in docker.instructions_of_type(f.content, "healthcheck")]
	count(hcs) == 0
	# Report at line 1 of the file.
	finding := {
		"rule_id": metadata.id,
		"message": "Add HEALTHCHECK instruction in your Dockerfile",
		"artifact_uri": f.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": "",
	}
}
