# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0001).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_docker_latest_tag

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0001",
	"name": "':latest' tag used",
	"description": "When using a 'FROM' statement you should use a specific tag to avoid uncontrolled behavior when the image is updated.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-use-specific-tags",
	"languages": ["dockerfile"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1357"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "supply-chain", "best-practices"],
}

# Aliases defined by FROM ... AS <alias> across all dockerfiles.
_all_aliases contains lower(stage.alias) if {
	some stage in docker.stages
	stage.alias != ""
}

findings contains finding if {
	some stage in docker.stages
	img := _image_part(stage.from_image)
	tag := _tag_part(stage.from_image)
	img != "scratch"
	img != ""
	not lower(img) in _all_aliases
	tag == "latest"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Specify a tag in the 'FROM' statement for image '%s'", [img]),
		"artifact_uri": stage.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": stage.from_line,
		"snippet": sprintf("FROM %s", [stage.from_image]),
	}
}

# Strip platform flags (e.g. --platform=linux/amd64) from FROM image.
_clean_image(raw) := out if {
	parts := regex.split(`\s+`, trim_space(raw))
	filtered := [p | some p in parts; not startswith(p, "--"); p != ""]
	count(filtered) > 0
	out := filtered[0]
} else := trim_space(raw)

_image_part(raw) := img if {
	ref := _clean_image(raw)
	not contains(ref, "$")
	colon_parts := split(ref, ":")
	count(colon_parts) > 1
	last := colon_parts[count(colon_parts) - 1]
	not contains(last, "/")
	img := substring(ref, 0, (count(ref) - count(last)) - 1)
} else := ref if {
	ref := _clean_image(raw)
	not contains(ref, "$")
	colon_parts := split(ref, ":")
	count(colon_parts) > 1
	last := colon_parts[count(colon_parts) - 1]
	contains(last, "/")
} else := ref if {
	ref := _clean_image(raw)
	not contains(ref, "$")
	not contains(ref, ":")
} else := ""

_tag_part(raw) := tag if {
	ref := _clean_image(raw)
	not contains(ref, "$")
	colon_parts := split(ref, ":")
	count(colon_parts) > 1
	last := colon_parts[count(colon_parts) - 1]
	not contains(last, "/")
	tag := last
} else := "latest" if {
	ref := _clean_image(raw)
	not contains(ref, "$")
	not contains(ref, ":")
} else := ""
