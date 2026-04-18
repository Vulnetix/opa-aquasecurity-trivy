# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0039).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: reports an informational finding on the first pod-bearing workload
# when no LimitRange document exists in the manifest bundle.

package vulnetix.rules.trivy_k8s_use_limit_range

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0039",
	"name": "limit range usage",
	"description": "Ensure that a LimitRange policy is configured to limit resource usage for namespaces or nodes.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-limit-range-usage",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-400"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "resources", "limitrange"],
}

_limit_range_count := count(k8s.resources("LimitRange"))

findings contains finding if {
	_limit_range_count == 0
	some r in k8s.resources_with_pod_templates
	# Emit on the first workload only by requiring that no earlier workload sorts before it.
	ref := sprintf("%s/%s/%s", [r.path, r.resource.kind, k8s.resource_name(r.resource)])
	refs := [s |
		some x in k8s.resources_with_pod_templates
		s := sprintf("%s/%s/%s", [x.path, x.resource.kind, k8s.resource_name(x.resource)])
	]
	ref == min(refs)
	finding := {
		"rule_id": metadata.id,
		"message": "No LimitRange configured; workloads will run without namespace-scoped request/limit defaults.",
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}
