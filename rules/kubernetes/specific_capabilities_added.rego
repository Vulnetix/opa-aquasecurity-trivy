# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0022).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_specific_capabilities_added

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0022",
	"name": "Specific capabilities added",
	"description": "According to pod security standard 'Capabilities', capabilities beyond the default set must not be added.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-non-default-capabilities",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "capabilities", "pss"],
}

findings contains finding if {
	some c in k8s.all_containers
	some cap in k8s.added_capabilities(c.container)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' adds non-default capability '%s'",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource), cap],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
