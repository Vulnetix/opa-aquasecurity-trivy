# Adapted from https://github.com/aquasecurity/trivy-checks (KSV014).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_file_system_not_read_only

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0014",
	"name": "Root file system is not read-only",
	"description": "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-use-readonly-filesystem",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-732"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "filesystem", "readonly"],
}

findings contains finding if {
	some c in k8s.all_containers
	not k8s.sc_bool_true(c.container, "readOnlyRootFilesystem")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Container '%s' of %s '%s' should set 'securityContext.readOnlyRootFilesystem' to true", [
			c.container.name, c.resource.kind, k8s.resource_name(c.resource),
		]),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
