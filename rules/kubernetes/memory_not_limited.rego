# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0018).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_memory_not_limited

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0018",
	"name": "Memory not limited",
	"description": "Enforcing memory limits prevents DoS via resource exhaustion.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-limit-memory",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-400"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "resources", "dos"],
}

findings contains finding if {
	some c in k8s.all_containers
	limits := object.get(object.get(c.container, "resources", {}), "limits", {})
	not _has_key(limits, "memory")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' should set 'resources.limits.memory'",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource)],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}

_has_key(o, k) if _ := o[k]
