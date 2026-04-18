# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0104).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_seccomp_profile_unconfined

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0104",
	"name": "Seccomp policies disabled",
	"description": "A program inside the container can bypass Seccomp protection policies.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-seccomp-unconfined",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "seccomp"],
}

_seccomp_type_for(c) := t if {
	sc := k8s.container_security_context(c.container)
	t := object.get(object.get(sc, "seccompProfile", {}), "type", "")
} else := t if {
	psc := k8s.pod_security_context(c.pod_template)
	t := object.get(object.get(psc, "seccompProfile", {}), "type", "")
}

findings contains finding if {
	some c in k8s.all_containers
	t := _seccomp_type_for(c)
	lower(t) == "unconfined"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' uses 'seccompProfile.type: Unconfined'",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource)],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
