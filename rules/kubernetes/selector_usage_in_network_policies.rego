# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0038).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_selector_usage_in_network_policies

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0038",
	"name": "Selector usage in network policies",
	"description": "Ensure that network policies selectors are applied to pods or namespaces to restricted ingress and egress traffic within the pod network.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-selector-usage-in-network-policies",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "networkpolicy"],
}

_has_selector(spec) if {
	ps := spec.podSelector
	_ := ps.matchLabels
}

_has_selector(spec) if {
	_ := spec.namespaceSelector
}

_has_selector(spec) if {
	_ := spec.podSelector
}

_has_selector(spec) if {
	some ing in object.get(spec, "ingress", [])
	some src in object.get(ing, "from", [])
	_ := src.namespaceSelector
}

_has_selector(spec) if {
	some ing in object.get(spec, "ingress", [])
	some src in object.get(ing, "from", [])
	_ := src.podSelector
}

_has_selector(spec) if {
	some eg in object.get(spec, "egress", [])
	some dst in object.get(eg, "to", [])
	_ := dst.namespaceSelector
}

_has_selector(spec) if {
	some eg in object.get(spec, "egress", [])
	some dst in object.get(eg, "to", [])
	_ := dst.podSelector
}

findings contains finding if {
	some d in k8s.resources("NetworkPolicy")
	spec := object.get(d.doc, "spec", {})
	not _has_selector(spec)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"NetworkPolicy '%s' should use podSelector and/or namespaceSelector to restrict traffic",
			[k8s.resource_name(d.doc)],
		),
		"artifact_uri": d.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": d.line,
		"snippet": sprintf("NetworkPolicy/%s", [k8s.resource_name(d.doc)]),
	}
}
