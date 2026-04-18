# Adapted from https://github.com/aquasecurity/trivy-checks (KSV054).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_attaching_pod_view_logs_realtime

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0054",
	"name": "Do not allow attaching to shell on pods",
	"description": "Check whether role permits attaching to shell on pods.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-attaching-shell-pods",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "pod-attach"],
}

_has_attach_and_get_pod(role_doc) if {
	rules := object.get(role_doc, "rules", [])
	some i
	a := rules[i]
	"pods/attach" in object.get(a, "resources", [])
	"create" in object.get(a, "verbs", [])

	some j
	j > i
	b := rules[j]
	"pods" in object.get(b, "resources", [])
	"get" in object.get(b, "verbs", [])
}

findings contains finding if {
	some r in k8s.roles
	_has_attach_and_get_pod(r.doc)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s '%s' permits attaching to shell on pods (pods/attach + pods:get)", [
			r.doc.kind, k8s.resource_name(r.doc),
		]),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s", [r.doc.kind, k8s.resource_name(r.doc)]),
	}
}
