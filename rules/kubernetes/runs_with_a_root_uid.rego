# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0105).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_runs_with_a_root_uid

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0105",
	"name": "Containers must not set runAsUser to 0",
	"description": "Containers should be forbidden from running with a root UID.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-containers-not-run-as-root",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "privilege", "pss"],
}

findings contains finding if {
	some c in k8s.all_containers
	sc := k8s.container_security_context(c.container)
	sc.runAsUser == 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' sets 'runAsUser: 0' (root UID)",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource)],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}

findings contains finding if {
	some r in k8s.resources_with_pod_templates
	psc := k8s.pod_security_context(r.pod_template)
	psc.runAsUser == 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' sets pod-level 'runAsUser: 0' (root UID)",
			[r.resource.kind, k8s.resource_name(r.resource)],
		),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}
