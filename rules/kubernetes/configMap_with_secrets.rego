# Adapted from https://github.com/aquasecurity/trivy-checks (KSV0109).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_configmap_with_secrets

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0109",
	"name": "ConfigMap with secrets",
	"description": "Storing secrets in configMaps is unsafe.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-configmap-with-secrets",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-798"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "configmap", "secret"],
}

_value_patterns := [
	`(?i)(password\s*(=|:))`,
	`(?i)(pass\s*(=|:))`,
	`(?i)(pword\s*(=|:))`,
	`(?i)(passphrase\s*(=|:))`,
	`(?i)(passwd\s*(=|:))`,
	`(?i)(secret\s*(=|:))`,
	`(?i)(secretkey\s*(=|:))`,
	`(?i)(appSecret\s*(=|:))`,
	`(?i)(clientSecret\s*(=|:))`,
	`(?i)(aws_access_key_id\s*(=|:))`,
	`(?i)(pswrd\s*(=|:))`,
	`(?i)(token\s*(=|:))`,
	`(?i)(pwd\s*(=|:))`,
]

_key_patterns := [
	`(?i)^password$`,
	`(?i)^pass$`,
	`(?i)^passphrase$`,
	`(?i)^passwd$`,
	`(?i)^secret$`,
	`(?i)^secretkey$`,
	`(?i)^appSecret$`,
	`(?i)^clientSecret$`,
	`(?i)^aws_access_key_id$`,
	`(?i)^token$`,
	`(?i)^pwd$`,
]

_configmap_has_secret_key(cm) if {
	some k, _ in object.get(cm, "data", {})
	some pattern in _key_patterns
	regex.match(pattern, k)
}

_configmap_has_secret_value(cm) if {
	some _, v in object.get(cm, "data", {})
	is_string(v)
	some pattern in _value_patterns
	regex.match(pattern, v)
}

findings contains finding if {
	some d in k8s.resources("ConfigMap")
	_configmap_has_secret_key(d.doc)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ConfigMap '%s' has a data key that looks like a secret", [k8s.resource_name(d.doc)]),
		"artifact_uri": d.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": d.line,
		"snippet": sprintf("ConfigMap/%s/data.key", [k8s.resource_name(d.doc)]),
	}
}

findings contains finding if {
	some d in k8s.resources("ConfigMap")
	_configmap_has_secret_value(d.doc)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("ConfigMap '%s' stores values that look like secrets", [k8s.resource_name(d.doc)]),
		"artifact_uri": d.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": d.line,
		"snippet": sprintf("ConfigMap/%s/data.value", [k8s.resource_name(d.doc)]),
	}
}
