# Adapted from https://github.com/aquasecurity/trivy-checks (KSV004).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_capabilities_no_drop_at_least_one

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0004",
	"name": "Default capabilities: some containers do not drop any",
	"description": "Security best practices require containers to run with minimal required capabilities.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-drop-unused-capabilities",
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

findings contains finding if {
	some c in k8s.all_containers
	count(k8s.dropped_capabilities(c.container)) == 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Container '%s' of %s '%s' should set 'securityContext.capabilities.drop'", [
			c.container.name, c.resource.kind, k8s.resource_name(c.resource),
		]),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
