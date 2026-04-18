# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0009).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_workdir_path_not_absolute

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0009",
	"name": "WORKDIR path not absolute",
	"description": "For clarity and reliability, you should always use absolute paths for your WORKDIR.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-user-absolute-workdir",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "workdir", "best-practices"],
}

findings contains finding if {
	some f in docker.dockerfiles
	some inst in docker.instructions_of_type(f.content, "workdir")
	arg := trim_space(inst.value)
	not _is_absolute(arg)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("WORKDIR path '%s' should be absolute", [arg]),
		"artifact_uri": f.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": inst.line,
		"snippet": inst.original,
	}
}

_is_absolute(arg) if regex.match(`^["']?/`, arg)

_is_absolute(arg) if regex.match(`^[A-Za-z]:\\`, arg)

_is_absolute(arg) if regex.match(`^\$[{]?[A-Za-z0-9_]+`, arg)
