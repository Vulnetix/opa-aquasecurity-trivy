# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0032).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_uses_untrusted_azure_registry

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0032",
	"name": "All container images must start with the *.azurecr.io domain",
	"description": "Containers should only use images from trusted registries.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-use-azure-image-prefix",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "images", "supply-chain", "azure"],
}

findings contains finding if {
	some c in k8s.all_containers
	image := object.get(c.container, "image", "")
	image != ""
	parts := split(image, "/")
	count(parts) > 1
	not endswith(parts[0], "azurecr.io")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' image '%s' is not hosted on *.azurecr.io",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource), image],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
