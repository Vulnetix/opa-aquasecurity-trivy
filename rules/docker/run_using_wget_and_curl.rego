# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0014).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_run_using_wget_and_curl

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0014",
	"name": "RUN using 'wget' and 'curl'",
	"description": "Avoid using both 'wget' and 'curl' since these tools have the same effect.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-standardise-remote-get",
	"languages": ["dockerfile"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "best-practices"],
}

# Per-stage: if any RUN uses wget and any RUN uses curl (excluding install
# sub-commands that may legitimately fetch dependencies), report the first
# RUN that uses wget.
findings contains finding if {
	some stage in docker.stages
	runs := [r | some r in stage.instructions; r.cmd == "run"]
	wget_runs := [r | some r in runs; _uses_tool(r.value, "wget")]
	curl_runs := [r | some r in runs; _uses_tool(r.value, "curl")]
	count(wget_runs) > 0
	count(curl_runs) > 0
	first := wget_runs[0]
	finding := {
		"rule_id": metadata.id,
		"message": "Shouldn't use both curl and wget",
		"artifact_uri": stage.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": first.line,
		"snippet": first.original,
	}
}

# Returns true if any sub-command (split by && / ;) starts with the tool name,
# ignoring package-install forms like "apt-get install curl".
_uses_tool(value, tool) if {
	some sub in docker.split_run(value)
	trimmed := trim_space(sub)
	not contains(trimmed, "install ")
	regex.match(sprintf(`^%s(\s|$)`, [tool]), trimmed)
}

# JSON exec form: ["curl", "..."] or ["wget", "..."].
_uses_tool(value, tool) if {
	docker.is_json_array(value)
	args := docker.json_exec_args(value)
	count(args) > 0
	args[0] == tool
}
