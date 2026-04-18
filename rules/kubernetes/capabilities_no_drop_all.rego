# Adapted from https://github.com/aquasecurity/trivy-checks (KSV003).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_capabilities_no_drop_all

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0003",
	"name": "Default capabilities: some containers do not drop all",
	"description": "The container should drop all default capabilities and add only those that are needed for its execution.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-drop-default-capabilities",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "capabilities", "least-privilege"],
}

_has_drop_all(container) if {
	some cap in k8s.dropped_capabilities(container)
	upper(cap) == "ALL"
}

findings contains finding if {
	some c in k8s.all_containers
	not _has_drop_all(c.container)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Container '%s' of %s '%s' should add 'ALL' to 'securityContext.capabilities.drop'", [
			c.container.name, c.resource.kind, k8s.resource_name(c.resource),
		]),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
