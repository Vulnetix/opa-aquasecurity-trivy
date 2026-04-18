# Adapted from https://github.com/aquasecurity/trivy-checks (KSV001).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_can_elevate_its_own_privileges

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0001",
	"name": "Can elevate its own privileges",
	"description": "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-self-privesc",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "privilege-escalation", "container"],
}

findings contains finding if {
	some c in k8s.all_containers
	sc := k8s.container_security_context(c.container)
	allow := object.get(sc, "allowPrivilegeEscalation", true)
	allow != false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Container '%s' of %s '%s' should set 'securityContext.allowPrivilegeEscalation' to false", [
			c.container.name, c.resource.kind, k8s.resource_name(c.resource),
		]),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
