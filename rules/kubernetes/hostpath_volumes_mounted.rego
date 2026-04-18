# Adapted from https://github.com/aquasecurity/trivy-checks (KSV023).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_hostpath_volumes_mounted

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0023",
	"name": "hostPath volumes mounted",
	"description": "According to pod security standard 'HostPath Volumes', HostPath volumes must be forbidden.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-mounted-hostpath",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-668"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "volume", "hostpath"],
}

findings contains finding if {
	some r in k8s.resources_with_pod_templates
	some vol in object.get(r.pod_template.spec, "volumes", [])
	object.get(vol, "hostPath", false) != false
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should not set 'spec.template.volumes.hostPath' (volume '%s')", [
			r.resource.kind, k8s.resource_name(r.resource), object.get(vol, "name", "<unnamed>"),
		]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s/volume=%s/hostPath", [r.resource.kind, k8s.resource_name(r.resource), object.get(vol, "name", "<unnamed>")]),
	}
}
