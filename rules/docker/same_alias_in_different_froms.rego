# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0012).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_same_alias_in_different_froms

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0012",
	"name": "Duplicate aliases defined in different FROMs",
	"description": "Different FROMs can't have the same alias defined.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-no-duplicate-alias",
	"languages": ["dockerfile"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "multistage", "best-practices"],
}

findings contains finding if {
	some s1 in docker.stages
	some s2 in docker.stages
	s1.alias != ""
	s2.alias != ""
	lower(s1.alias) == lower(s2.alias)
	s1.from_index < s2.from_index
	s1.path == s2.path
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Duplicate aliases '%s' are found in different FROMs", [lower(s1.alias)]),
		"artifact_uri": s1.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": s1.from_line,
		"snippet": sprintf("FROM %s AS %s", [s1.from_image, s1.alias]),
	}
}
