# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0021).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_runs_with_gid_le_10000

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0021",
	"name": "Runs with GID <= 10000",
	"description": "Force the container to run with group ID > 10000 to avoid conflicts with the host's user table.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-use-high-gid",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "privilege"],
}

_container_group(c) := g if {
	sc := k8s.container_security_context(c.container)
	g := sc.runAsGroup
} else := g if {
	psc := k8s.pod_security_context(c.pod_template)
	g := psc.runAsGroup
}

findings contains finding if {
	some c in k8s.all_containers
	g := _container_group(c)
	g <= 10000
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' runs with GID %d (must be > 10000)",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource), g],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}

findings contains finding if {
	some c in k8s.all_containers
	not _container_group(c)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' does not set 'runAsGroup' (should be > 10000)",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource)],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
