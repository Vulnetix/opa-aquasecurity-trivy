# Adapted from https://github.com/aquasecurity/trivy-checks (KSV002).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_apparmor_policy_disabled

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0002",
	"name": "Runtime/Default AppArmor profile not set",
	"description": "According to pod security standard 'AppArmor', the AppArmor key must be set to the runtime/default profile or to be undefined.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-use-default-apparmor-profile",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-284"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "apparmor", "mandatory-access-control"],
}

findings contains finding if {
	some c in k8s.all_containers
	annotations := object.get(object.get(c.pod_template, "metadata", {}), "annotations", {})
	key := sprintf("container.apparmor.security.beta.kubernetes.io/%s", [c.container.name])
	val := object.get(annotations, key, "runtime/default")
	val != "runtime/default"
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Container '%s' of %s '%s' should use AppArmor profile 'runtime/default' (got '%s')", [
			c.container.name, c.resource.kind, k8s.resource_name(c.resource), val,
		]),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}
