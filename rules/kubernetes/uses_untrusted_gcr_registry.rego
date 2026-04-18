# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0033).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_uses_untrusted_gcr_registry

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0033",
	"name": "All container images must start with a GCR domain",
	"description": "Containers should only use images from trusted GCR registries.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-use-gcr-domain",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "images", "supply-chain", "gcr", "gcp"],
}

_trusted_gcr := ["gcr.io", "us.gcr.io", "eu.gcr.io", "asia.gcr.io"]

_is_trusted(registry) if {
	some suffix in _trusted_gcr
	endswith(registry, suffix)
}

findings contains finding if {
	some c in k8s.all_containers
	image := object.get(c.container, "image", "")
	image != ""
	parts := split(image, "/")
	count(parts) > 1
	not _is_trusted(parts[0])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' image '%s' is not from a trusted GCR registry",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource), image],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
