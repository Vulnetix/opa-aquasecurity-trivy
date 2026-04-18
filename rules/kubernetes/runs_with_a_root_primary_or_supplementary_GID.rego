# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0116).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_runs_with_a_root_primary_or_supplementary_gid

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0116",
	"name": "Runs with a root primary or supplementary GID",
	"description": "According to pod security standard 'Non-root groups', containers should be forbidden from running with a root primary or supplementary GID.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-primary-supplementary-gid",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "privilege", "pss"],
}

findings contains finding if {
	some c in k8s.all_containers
	sc := k8s.container_security_context(c.container)
	sc.runAsGroup == 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' sets 'runAsGroup: 0' (root GID)",
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
	psc.runAsGroup == 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' sets pod-level 'runAsGroup: 0' (root GID)",
			[r.resource.kind, k8s.resource_name(r.resource)],
		),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}

findings contains finding if {
	some r in k8s.resources_with_pod_templates
	psc := k8s.pod_security_context(r.pod_template)
	psc.fsGroup == 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' sets pod-level 'fsGroup: 0' (root GID)",
			[r.resource.kind, k8s.resource_name(r.resource)],
		),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}

findings contains finding if {
	some r in k8s.resources_with_pod_templates
	psc := k8s.pod_security_context(r.pod_template)
	some gid in object.get(psc, "supplementalGroups", [])
	gid == 0
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' sets pod-level 'supplementalGroups' containing 0 (root GID)",
			[r.resource.kind, k8s.resource_name(r.resource)],
		),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}
