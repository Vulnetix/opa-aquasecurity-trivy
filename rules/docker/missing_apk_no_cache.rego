# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0025).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_missing_apk_no_cache

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0025",
	"name": "'apk add' is missing '--no-cache'",
	"description": "You should use 'apk add' with '--no-cache' to clean package cached data and reduce image size.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-purge-apk-package-cache",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "alpine", "apk", "image-size"],
}

findings contains finding if {
	some run in docker.run_cmds
	some sub in docker.split_run(run.value)
	_apk_add_without_no_cache(sub)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'--no-cache' is missed: %s", [sub]),
		"artifact_uri": run.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": run.line,
		"snippet": run.original,
	}
}

_apk_add_without_no_cache(cmd) if {
	regex.match(`(^|\s)apk(\s+-{1,2}[a-zA-Z]+)*\s+add(\s|$)`, cmd)
	not contains(cmd, "--no-cache")
}
