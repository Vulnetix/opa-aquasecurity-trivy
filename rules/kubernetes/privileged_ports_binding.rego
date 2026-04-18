# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0117).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_privileged_ports_binding

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0117",
	"name": "Prevent binding to privileged ports",
	"description": "The ports which are lower than 1024 receive and transmit various sensitive and privileged data. Allowing containers to use them can bring serious implications.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-privilege-port-binding",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "networking", "privilege"],
}

findings contains finding if {
	some c in k8s.all_containers
	some p in object.get(c.container, "ports", [])
	cp := object.get(p, "containerPort", 0)
	is_number(cp)
	cp > 0
	cp < 1024
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' binds privileged containerPort %d",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource), cp],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s/port=%d", [c.resource.kind, k8s.resource_name(c.resource), c.container.name, cp]),
	}
}

findings contains finding if {
	some c in k8s.all_containers
	some p in object.get(c.container, "ports", [])
	hp := object.get(p, "hostPort", 0)
	is_number(hp)
	hp > 0
	hp < 1024
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' binds privileged hostPort %d",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource), hp],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s/hostPort=%d", [c.resource.kind, k8s.resource_name(c.resource), c.container.name, hp]),
	}
}
