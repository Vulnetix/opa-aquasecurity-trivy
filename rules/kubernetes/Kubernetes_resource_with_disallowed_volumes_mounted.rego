# Adapted from https://github.com/aquasecurity/trivy-checks (KSV121).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_kubernetes_resource_with_disallowed_volumes_mounted

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0121",
	"name": "Kubernetes resource with disallowed volumes mounted",
	"description": "HostPath presents many security risks and as a security practice it is better to avoid critical host paths mounts.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-k8s-with-disallowed-volumes",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-668"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "volume", "hostpath"],
}

_disallowed := {"/", "/boot", "/dev", "/etc", "/lib", "/proc", "/sys", "/usr", "/var/lib/docker"}

findings contains finding if {
	some r in k8s.resources_with_pod_templates
	some vol in object.get(r.pod_template.spec, "volumes", [])
	path := object.get(object.get(vol, "hostPath", {}), "path", "")
	path in _disallowed
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' mounts disallowed hostPath '%s'", [
			r.resource.kind, k8s.resource_name(r.resource), path,
		]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s/hostPath=%s", [r.resource.kind, k8s.resource_name(r.resource), path]),
	}
}
