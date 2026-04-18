# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0025).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_selinux_custom_options_set

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0025",
	"name": "SELinux custom options set",
	"description": "According to pod security standard 'SElinux', setting custom SELinux options should be disallowed.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-custom-selinux-options",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "selinux", "pss"],
}

_allowed_types := {"container_t", "container_init_t", "container_kvm_t"}

_forbidden_fields := {"role", "user"}

_selinux_from_container(c) := options if {
	sc := k8s.container_security_context(c.container)
	options := sc.seLinuxOptions
}

_selinux_from_pod(r) := options if {
	psc := k8s.pod_security_context(r.pod_template)
	options := psc.seLinuxOptions
}

# Container-level disallowed type
findings contains finding if {
	some c in k8s.all_containers
	options := _selinux_from_container(c)
	options.type
	not options.type in _allowed_types
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' uses disallowed seLinuxOptions.type '%s'",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource), options.type],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}

# Pod-level disallowed type
findings contains finding if {
	some r in k8s.resources_with_pod_templates
	options := _selinux_from_pod(r)
	options.type
	not options.type in _allowed_types
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' sets pod-level seLinuxOptions.type '%s' (disallowed)",
			[r.resource.kind, k8s.resource_name(r.resource), options.type],
		),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}

# Container-level forbidden property (role/user)
findings contains finding if {
	some c in k8s.all_containers
	options := _selinux_from_container(c)
	some field in _forbidden_fields
	_ := options[field]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"Container '%s' of %s '%s' sets disallowed seLinuxOptions.%s",
			[c.container.name, c.resource.kind, k8s.resource_name(c.resource), field],
		),
		"artifact_uri": c.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": c.line,
		"snippet": sprintf("%s/%s/container=%s", [c.resource.kind, k8s.resource_name(c.resource), c.container.name]),
	}
}

# Pod-level forbidden property (role/user)
findings contains finding if {
	some r in k8s.resources_with_pod_templates
	options := _selinux_from_pod(r)
	some field in _forbidden_fields
	_ := options[field]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' sets disallowed pod-level seLinuxOptions.%s",
			[r.resource.kind, k8s.resource_name(r.resource), field],
		),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s", [r.resource.kind, k8s.resource_name(r.resource)]),
	}
}
