# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0013).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_uses_image_tag_latest

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0013",
	"name": "Image tag ':latest' used",
	"description": "It is best to avoid using the ':latest' image tag when deploying containers in production. Doing so makes it hard to track which version of the image is running, and hard to roll back the version.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-use-specific-tags",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "images", "supply-chain"],
}

# Image is considered tagged if it references a digest.
_is_tagged(image) if contains(image, "@")

# Or has an explicit non-"latest" tag on the last path segment.
_is_tagged(image) if {
	not contains(image, "@")
	parts := split(image, "/")
	last := parts[count(parts) - 1]
	tag_parts := split(last, ":")
	count(tag_parts) > 1
	tag := tag_parts[count(tag_parts) - 1]
	tag != "latest"
}

findings contains finding if {
	some c in k8s.all_containers
	image := object.get(c.container, "image", "")
	image != ""
	not _is_tagged(image)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' uses untagged or ':latest' image '%s'",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource), image],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
