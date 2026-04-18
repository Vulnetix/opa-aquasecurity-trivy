# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0012).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_runs_as_root

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0012",
	"name": "Runs as root user",
	"description": "Force the running image to run as a non-root user to ensure least privileges.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-root",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "privilege", "pss"],
}

_pod_run_as_non_root(pt) if {
	psc := k8s.pod_security_context(pt)
	psc.runAsNonRoot == true
}

findings contains finding if {
	some c in k8s.all_containers
	not k8s.sc_bool_true(c.container, "runAsNonRoot")
	not _pod_run_as_non_root(c.pod_template)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' should set 'securityContext.runAsNonRoot: true'",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource)],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
