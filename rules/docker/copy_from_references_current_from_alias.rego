# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0006).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_copy_from_references_current_from_alias

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0006",
	"name": "COPY '--from' referring to the current image",
	"description": "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-no-self-referencing-copy-from",
	"languages": ["dockerfile"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-1188"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "multistage", "best-practices"],
}

findings contains finding if {
	some stage in docker.stages
	stage.alias != ""
	some inst in stage.instructions
	inst.cmd == "copy"
	from_alias := _copy_from_alias(inst.value)
	lower(from_alias) == lower(stage.alias)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("'COPY --from' should not mention current alias '%s' since it is impossible to copy from itself", [from_alias]),
		"artifact_uri": stage.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": inst.line,
		"snippet": inst.original,
	}
}

# Extract alias from `--from=<alias>` in a COPY instruction value.
_copy_from_alias(value) := alias if {
	parts := regex.split(`\s+`, value)
	some p in parts
	startswith(p, "--from=")
	alias := substring(p, count("--from="), -1)
}
