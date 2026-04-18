# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0005).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_add_instead_of_copy

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0005",
	"name": "ADD instead of COPY",
	"description": "You should use COPY instead of ADD unless you want to extract a tar file. Note that an ADD command will extract a tar file, which adds the risk of Zip-based vulnerabilities. Accordingly, it is advised to use a COPY command, which does not extract tar files.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-use-copy-over-add",
	"languages": ["dockerfile"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-829"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "best-practices", "supply-chain"],
}

findings contains finding if {
	some add in docker.add_cmds
	_is_unnecessary_add(add.value)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Consider using 'COPY %s' command instead of 'ADD %s'", [add.value, add.value]),
		"artifact_uri": add.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": add.line,
		"snippet": add.original,
	}
}

_is_unnecessary_add(value) if {
	every needle in {".tar", "http://", "https://", "git@"} {
		not contains(value, needle)
	}
}
