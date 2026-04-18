# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0108).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_service_with_externalip

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0108",
	"name": "Service with External IP",
	"description": "Services with external IP addresses allows direct access from the internet and might expose risk for CVE-2020-8554.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-svc-with-extip",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "networking", "service"],
}

findings contains finding if {
	some d in k8s.resources("Service")
	ips := object.get(object.get(d.doc, "spec", {}), "externalIPs", [])
	count(ips) > 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Service '%s' sets spec.externalIPs %v",
			[k8s.resource_name(d.doc), ips],
		),
		"artifact_uri": d.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": d.line,
		"snippet": sprintf("Service/%s", [k8s.resource_name(d.doc)]),
	}
}
