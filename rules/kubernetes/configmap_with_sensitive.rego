# Adapted from https://github.com/aquasecurity/trivy-checks (KSV01010).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_configmap_with_sensitive

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-1010",
	"name": "ConfigMap with sensitive content",
	"description": "Storing sensitive content such as usernames and email addresses in configMaps is unsafe.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-configmap-with-sensitive",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-359"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "configmap", "pii"],
}

_value_patterns := [
	`(?i)(username\s*(=|:))`,
	`(?i)(email\s*(=|:))`,
	`([a-zA-Z0-9_.\-]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)`,
	`(?i)(phone\s*(=|:))`,
	`(?i)(iban\s*(=|:))`,
]

_key_patterns := [
	`(?i)^username$`,
	`(?i)^email$`,
	`(?i)^phone$`,
	`(?i)^iban$`,
]

_cm_has_sensitive_key(cm) if {
	some k, _ in object.get(cm, "data", {})
	some pattern in _key_patterns
	regex.match(pattern, k)
}

_cm_has_sensitive_value(cm) if {
	some _, v in object.get(cm, "data", {})
	is_string(v)
	some pattern in _value_patterns
	regex.match(pattern, v)
}

findings contains finding if {
	some d in k8s.resources("ConfigMap")
	_cm_has_sensitive_key(d.doc)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ConfigMap '%s' has a data key that stores sensitive data", [k8s.resource_name(d.doc)]),
		"artifact_uri": d.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": d.line,
		"snippet": sprintf("ConfigMap/%s/data.key", [k8s.resource_name(d.doc)]),
	}
}

findings contains finding if {
	some d in k8s.resources("ConfigMap")
	_cm_has_sensitive_value(d.doc)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ConfigMap '%s' stores sensitive values", [k8s.resource_name(d.doc)]),
		"artifact_uri": d.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": d.line,
		"snippet": sprintf("ConfigMap/%s/data.value", [k8s.resource_name(d.doc)]),
	}
}
