# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0022).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_maintainer_is_deprecated

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0022",
	"name": "Deprecated MAINTAINER used",
	"description": "MAINTAINER has been deprecated since Docker 1.13.0. Use LABEL instead.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-no-maintainer",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "deprecated", "best-practices"],
}

findings contains finding if {
	some m in docker.maintainer_cmds
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("MAINTAINER should not be used: 'MAINTAINER %s'", [m.value]),
		"artifact_uri": m.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": m.line,
		"snippet": m.original,
	}
}
