# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0102).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_tiller_is_deployed

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0102",
	"name": "Tiller Is Deployed",
	"description": "Check if Helm Tiller component is deployed.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-tiller",
	"languages": ["yaml"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-1104"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "helm", "tiller"],
}

# Flag any container image referencing tiller.
findings contains finding if {
	some c in k8s.all_containers
	image := object.get(c.container, "image", "")
	contains(image, "tiller")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' uses Tiller image '%s'",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource), image],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}

# Flag any workload whose metadata.name contains "tiller".
findings contains finding if {
	some r in k8s.resources_with_pod_templates
	contains(k8s.resource_name(r.resource), "tiller")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' appears to be a Tiller deployment",
			[r.resource.kind, k8s.resource_name(r.resource)],
		),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}

# Flag workloads labelled as tiller/helm.
findings contains finding if {
	some r in k8s.resources_with_pod_templates
	labels := object.get(object.get(r.resource, "metadata", {}), "labels", {})
	_is_tiller_labels(labels)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' carries Tiller/Helm labels",
			[r.resource.kind, k8s.resource_name(r.resource)],
		),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}

_is_tiller_labels(labels) if labels.app == "helm"

_is_tiller_labels(labels) if labels.name == "tiller"
