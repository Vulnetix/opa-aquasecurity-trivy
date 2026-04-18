# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0036).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_protecting_pod_service_account_tokens

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0036",
	"name": "Protecting Pod service account tokens",
	"description": "Ensure that Pod specifications disable the secret token being mounted by setting automountServiceAccountToken: false.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-auto-mount-service-token",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-732"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "serviceaccount"],
}

findings contains finding if {
	some r in k8s.resources_with_pod_templates
	object.get(r.pod_template.spec, "automountServiceAccountToken", true) == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' should set 'automountServiceAccountToken: false'",
			[r.resource.kind, k8s.resource_name(r.resource)],
		),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}
