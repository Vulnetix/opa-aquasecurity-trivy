# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0030).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_runtime_default_seccomp_profile_not_set

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0030",
	"name": "Runtime/Default Seccomp profile not set",
	"description": "According to pod security standard 'Seccomp', the RuntimeDefault seccomp profile must be required, or allow specific additional profiles.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-use-default-seccomp",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-693"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "seccomp", "pss"],
}

_valid_profiles := {"RuntimeDefault", "Localhost"}

_seccomp_type(c) := t if {
	sc := k8s.container_security_context(c.container)
	t := object.get(object.get(sc, "seccompProfile", {}), "type", "")
} else := t if {
	psc := k8s.pod_security_context(c.pod_template)
	t := object.get(object.get(psc, "seccompProfile", {}), "type", "")
}

_has_legacy_annotation(pt) if {
	anno := object.get(object.get(pt, "metadata", {}), "annotations", {})
	_ := anno["seccomp.security.alpha.kubernetes.io/pod"]
}

findings contains finding if {
	some c in k8s.all_containers
	not _has_legacy_annotation(c.pod_template)
	t := _seccomp_type(c)
	not t in _valid_profiles
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' should set 'seccompProfile.type' to 'RuntimeDefault' or 'Localhost'",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource)],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
