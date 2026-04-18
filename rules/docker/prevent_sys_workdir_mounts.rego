# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0030).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_prevent_sys_workdir_mounts

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0030",
	"name": "WORKDIR should not be mounted on system dirs",
	"description": "WORKDIR should not be mounted on system directories to avoid container breakouts.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-avoid-sys-workdir-mounts",
	"languages": ["dockerfile"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "workdir", "container-breakout"],
}

_sysdirs := {"/proc/", "/boot/", "/dev/", "/initrd/", "/lost+found/"}

findings contains finding if {
	some f in docker.dockerfiles
	some inst in docker.instructions_of_type(f.content, "workdir")
	arg := trim(trim_space(inst.value), "\"")
	some prefix in _sysdirs
	startswith(arg, prefix)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("WORKDIR path '%s' should not mount system directories", [arg]),
		"artifact_uri": f.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": inst.line,
		"snippet": inst.original,
	}
}
