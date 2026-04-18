# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0027).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_non_default_proc_masks_set

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0027",
	"name": "Non-default /proc masks set",
	"description": "According to pod security standard '/proc Mount Type', the default /proc masks are set up to reduce attack surface, and should be required.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-custom-proc-mask",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-732"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "pss", "hardening"],
}

findings contains finding if {
	some c in k8s.all_containers
	sc := k8s.container_security_context(c.container)
	_ := sc.procMount
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' sets a custom 'procMount'",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource)],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
