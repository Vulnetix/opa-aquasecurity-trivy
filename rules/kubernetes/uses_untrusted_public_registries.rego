# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0034).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_uses_untrusted_public_registries

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0034",
	"name": "Container images from public registries used",
	"description": "Container images must not start with an empty prefix or a defined public registry domain.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-public-registries",
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

_untrusted_public := ["docker.io", "ghcr.io"]

# Image has an explicit untrusted public registry prefix.
findings contains finding if {
	some c in k8s.all_containers
	image := object.get(c.container, "image", "")
	image != ""
	some prefix in _untrusted_public
	startswith(image, prefix)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' image '%s' references a public registry",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource), image],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}

# Image without an explicit registry prefix (implicit docker.io).
findings contains finding if {
	some c in k8s.all_containers
	image := object.get(c.container, "image", "")
	image != ""
	parts := split(image, "/")
	count(parts) > 0
	not contains(parts[0], ".")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' image '%s' has no explicit registry prefix",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource), image],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
