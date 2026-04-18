# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0125).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# The original rule reads an overridable allow list from data.ksv0125;
# this port uses a static default trusted set (Azure + ECR + GCR suffixes).

package vulnetix.rules.trivy_k8s_uses_untrusted_registry

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0125",
	"name": "Restrict container images to trusted registries",
	"description": "Ensure that all containers use images only from trusted registry domains.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-use-trusted-registry",
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

_trusted_suffixes := [
	"azurecr.io",
	"gcr.io",
	"us.gcr.io",
	"eu.gcr.io",
	"asia.gcr.io",
	"ecr.us-east-2.amazonaws.com",
	"ecr.us-east-1.amazonaws.com",
	"ecr.us-west-1.amazonaws.com",
	"ecr.us-west-2.amazonaws.com",
	"ecr.af-south-1.amazonaws.com",
	"ecr.ap-east-1.amazonaws.com",
	"ecr.ap-south-1.amazonaws.com",
	"ecr.ap-northeast-2.amazonaws.com",
	"ecr.ap-southeast-1.amazonaws.com",
	"ecr.ap-southeast-2.amazonaws.com",
	"ecr.ap-northeast-1.amazonaws.com",
	"ecr.ca-central-1.amazonaws.com",
	"ecr.cn-north-1.amazonaws.com.cn",
	"ecr.cn-northwest-1.amazonaws.com.cn",
	"ecr.eu-central-1.amazonaws.com",
	"ecr.eu-west-1.amazonaws.com",
	"ecr.eu-west-2.amazonaws.com",
	"ecr.eu-south-1.amazonaws.com",
	"ecr.eu-west-3.amazonaws.com",
	"ecr.eu-north-1.amazonaws.com",
	"ecr.me-south-1.amazonaws.com",
	"ecr.sa-east-1.amazonaws.com",
	"ecr.us-gov-east-1.amazonaws.com",
	"ecr.us-gov-west-1.amazonaws.com",
]

_is_trusted(registry) if {
	some suffix in _trusted_suffixes
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
			"Container '%s' of %s '%s' image '%s' is not from a trusted registry",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource), image],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
