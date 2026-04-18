# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0047).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_privilege_escalation_from_node_proxy

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0047",
	"name": "Do not allow privilege escalation from node proxy",
	"description": "Check whether role permits privilege escalation from node proxy.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-privilege-escalation-from-node-proxy",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-269"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "rbac"],
}

_node_proxy_verbs := {"get", "create"}

findings contains finding if {
	some rr in k8s.role_rules
	some resource in object.get(rr.rule, "resources", [])
	resource == "nodes/proxy"
	some verb in object.get(rr.rule, "verbs", [])
	verb in _node_proxy_verbs
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' permits '%s' on 'nodes/proxy' (privilege escalation via node proxy)",
			[rr.role.kind, k8s.resource_name(rr.role), verb],
		),
		"artifact_uri": rr.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": rr.line,
		"snippet": sprintf("%s/%s", [rr.role.kind, k8s.resource_name(rr.role)]),
	}
}
