# Adapted from https://github.com/aquasecurity/trivy-checks (KSV010).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_host_pid

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0010",
	"name": "Access to host PID",
	"description": "Sharing the host's PID namespace allows visibility on host processes, potentially leaking information such as environment variables and configuration.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-host-pid",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-668"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "host", "pid"],
}

findings contains finding if {
	some r in k8s.resources_with_pod_templates
	object.get(r.pod_template.spec, "hostPID", false) == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should not set 'spec.template.spec.hostPID' to true", [
			r.resource.kind, k8s.resource_name(r.resource),
		]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s/hostPID=true", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}
