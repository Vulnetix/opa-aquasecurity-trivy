# Adapted from https://github.com/aquasecurity/trivy-checks (KSV106).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_drop_all_capabilities_only_add_net_bind_service

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0106",
	"name": "Container capabilities must only include NET_BIND_SERVICE",
	"description": "Containers must drop ALL capabilities, and are only permitted to add back the NET_BIND_SERVICE capability.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-drop-caps-add-bind-svc",
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
		"message": sprintf("Container '%s' of %s '%s' must drop ALL capabilities", [
			c.container.name, c.resource.kind, k8s.resource_name(c.resource),
		]),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s/drop", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}

findings contains finding if {
	some c in k8s.all_containers
	some add in k8s.added_capabilities(c.container)
	upper(add) != "NET_BIND_SERVICE"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Container '%s' of %s '%s' should only add NET_BIND_SERVICE capability (found '%s')", [
			c.container.name, c.resource.kind, k8s.resource_name(c.resource), add,
		]),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s/add=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name, add]),
	}
}
