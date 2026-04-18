# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0002).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_root_user

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0002",
	"name": "Image user should not be 'root'",
	"description": "Running containers with 'root' user can lead to a container escape situation. It is a best practice to run containers as non-root users, which can be done by adding a 'USER' statement to the Dockerfile.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-least-privilege-user",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-250", "CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "least-privilege", "user"],
}

# No USER instruction at all.
findings contains finding if {
	some f in docker.dockerfiles
	users := [u | some u in docker.instructions_of_type(f.content, "user")]
	count(users) < 1
	finding := {
		"rule_id": metadata.id,
		"message": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
		"artifact_uri": f.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": 1,
		"snippet": "",
	}
}

# Last USER is root or UID 0.
findings contains finding if {
	some f in docker.dockerfiles
	users := [u | some u in docker.instructions_of_type(f.content, "user")]
	count(users) > 0
	last := users[count(users) - 1]
	user_arg := _first_token(last.value)
	_is_root(user_arg)
	finding := {
		"rule_id": metadata.id,
		"message": "Last USER command in Dockerfile should not be 'root'",
		"artifact_uri": f.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": last.line,
		"snippet": last.original,
	}
}

_first_token(value) := tok if {
	parts := regex.split(`\s+`, trim_space(value))
	count(parts) > 0
	tok := parts[0]
} else := ""

_is_root(arg) if regex.match(`^root(:.+){0,1}$`, arg)

_is_root(arg) if regex.match(`^0(:.+){0,1}$`, arg)
