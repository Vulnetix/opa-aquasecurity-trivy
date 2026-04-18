# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0120).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_sys_module_capability

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0120",
	"name": "SYS_MODULE capability added",
	"description": "The SYS_MODULE capability grants attackers the ability to install and remove kernel modules, posing serious security risks.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-sysmodule-capability",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "capabilities"],
}

findings contains finding if {
	some c in k8s.all_containers
	"SYS_MODULE" in k8s.added_capabilities(c.container)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' adds capability 'SYS_MODULE'",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource)],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
