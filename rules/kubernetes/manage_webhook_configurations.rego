# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0114).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_manage_webhook_configurations

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0114",
	"name": "Manage webhookconfigurations",
	"description": "Webhooks can silently intercept or actively mutate/block resources as they are being created or updated. This includes secrets and pod specs.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-manage-webhook",
	"languages": ["yaml"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac", "webhook"],
}

_write_verbs := {"create", "update", "patch", "delete", "deletecollection", "impersonate", "*"}

_webhook_resources := {"mutatingwebhookconfigurations", "validatingwebhookconfigurations"}

findings contains finding if {
	some rr in k8s.role_rules
	some resource in object.get(rr.rule, "resources", [])
	resource in _webhook_resources
	some verb in object.get(rr.rule, "verbs", [])
	verb in _write_verbs
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' grants '%s' on webhook resource '%s'",
			[rr.role.kind, k8s.resource_name(rr.role), verb, resource],
		),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("%s/%s", [rr.role.kind, k8s.resource_name(rr.role)]),
	}
}
