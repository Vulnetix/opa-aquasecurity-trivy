# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0103).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_windows_host_process

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0103",
	"name": "Access to host process",
	"description": "Windows pods offer the ability to run HostProcess containers which enable privileged access to the Windows node.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-hostprocess-containers",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "windows", "privilege"],
}

findings contains finding if {
	some c in k8s.all_containers
	sc := k8s.container_security_context(c.container)
	object.get(object.get(sc, "windowsOptions", {}), "hostProcess", false) == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' enables Windows hostProcess",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource)],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}

findings contains finding if {
	some r in k8s.resources_with_pod_templates
	psc := k8s.pod_security_context(r.pod_template)
	object.get(object.get(psc, "windowsOptions", {}), "hostProcess", false) == true
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' enables pod-level Windows hostProcess",
			[r.resource.kind, k8s.resource_name(r.resource)],
		),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}
