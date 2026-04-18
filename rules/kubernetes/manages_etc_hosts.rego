# Adapted from https://github.com/aquasecurity/trivy-checks (KSV007).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_manages_etc_hosts

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0007",
	"name": "Manages /etc/hosts",
	"description": "Managing /etc/hosts aliases can prevent the container engine from modifying the file after a pod's containers have already been started.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-hostaliases",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-16"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "hostaliases", "dns"],
}

findings contains finding if {
	some r in k8s.resources_with_pod_templates
	aliases := object.get(r.pod_template.spec, "hostAliases", [])
	count(aliases) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should not set spec.template.spec.hostAliases", [
			r.resource.kind, k8s.resource_name(r.resource),
		]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s/hostAliases", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}
