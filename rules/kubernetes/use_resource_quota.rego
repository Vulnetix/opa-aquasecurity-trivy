# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0040).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Simplified: reports an informational finding on the first pod-bearing workload
# when no ResourceQuota document exists in the manifest bundle.

package vulnetix.rules.trivy_k8s_use_resource_quota

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0040",
	"name": "resource quota usage",
	"description": "Ensure that a ResourceQuota policy is configured to limit aggregate resource usage within a namespace.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-resource-quota-usage",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-400"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "resources", "resourcequota"],
}

_quota_count := count(k8s.resources("ResourceQuota"))

findings contains finding if {
	_quota_count == 0
	some r in k8s.resources_with_pod_templates
	ref := sprintf("%s/%s/%s", [r.path, r.resource.kind, k8s.resource_name(r.resource)])
	refs := [s |
		some x in k8s.resources_with_pod_templates
		s := sprintf("%s/%s/%s", [x.path, x.resource.kind, k8s.resource_name(x.resource)])
	]
	ref == min(refs)
	finding := {
		"rule_id": metadata.id,
		"message": "No ResourceQuota configured; namespaces have no aggregate resource caps.",
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}
