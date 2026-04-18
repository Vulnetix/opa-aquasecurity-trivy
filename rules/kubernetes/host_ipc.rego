# Adapted from https://github.com/aquasecurity/trivy-checks (KSV008).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_host_ipc

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0008",
	"name": "Access to host IPC namespace",
	"description": "Sharing the host's IPC namespace allows container processes to communicate with processes on the host.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-shared-ipc-namespace",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-668"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "host", "ipc"],
}

findings contains finding if {
	some r in k8s.resources_with_pod_templates
	object.get(r.pod_template.spec, "hostIPC", false) == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' should not set 'spec.template.spec.hostIPC' to true", [
			r.resource.kind, k8s.resource_name(r.resource),
		]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s/hostIPC=true", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}
