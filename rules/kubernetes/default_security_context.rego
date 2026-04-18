# Adapted from https://github.com/aquasecurity/trivy-checks (KSV118).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_default_security_context

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0118",
	"name": "Default security context configured",
	"description": "Security context controls the allocation of security parameters for the pod/container/volume, ensuring the appropriate level of protection. Relying on default security context may expose vulnerabilities to potential attacks that rely on privileged access.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-default-security-context",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-1188"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "security-context", "defaults"],
}

findings contains finding if {
	some r in k8s.resources_with_pod_templates
	pod_sc := k8s.pod_security_context(r.pod_template)
	count(pod_sc) == 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' is using the default pod security context, which allows root privileges", [
			r.resource.kind, k8s.resource_name(r.resource),
		]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s/podSpec.securityContext", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}

findings contains finding if {
	some c in k8s.all_containers
	sc := k8s.container_security_context(c.container)
	count(sc) == 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Container '%s' of %s '%s' is using the default security context", [
			c.container.name, c.resource.kind, k8s.resource_name(c.resource),
		]),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s/securityContext", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
