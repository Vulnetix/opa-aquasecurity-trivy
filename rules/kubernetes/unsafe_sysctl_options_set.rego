# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0026).
# Ported to the Vulnetix Rego input schema (input.file_contents).
# Uses the broadest allowed-sysctl set (1.32 baseline) for static YAML analysis.

package vulnetix.rules.trivy_k8s_unsafe_sysctl_options_set

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0026",
	"name": "Unsafe sysctl options set",
	"description": "Sysctls can disable security mechanisms or affect all containers on a host, and should be disallowed except for an allowed 'safe' subset.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-unsafe-sysctl",
	"languages": ["yaml"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": ["CWE-250"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "sysctl", "pss"],
}

_allowed_sysctls := {
	"kernel.shm_rmid_forced",
	"net.ipv4.ip_local_port_range",
	"net.ipv4.ip_local_reserved_ports",
	"net.ipv4.ip_unprivileged_port_start",
	"net.ipv4.tcp_syncookies",
	"net.ipv4.ping_group_range",
	"net.ipv4.tcp_keepalive_time",
	"net.ipv4.tcp_fin_timeout",
	"net.ipv4.tcp_keepalive_intvl",
	"net.ipv4.tcp_keepalive_probes",
	"net.ipv4.tcp_rmem",
	"net.ipv4.tcp_wmem",
}

findings contains finding if {
	some r in k8s.resources_with_pod_templates
	psc := k8s.pod_security_context(r.pod_template)
	some s in object.get(psc, "sysctls", [])
	name := object.get(s, "name", "")
	name != ""
	not name in _allowed_sysctls
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' sets unsafe sysctl '%s'",
			[r.resource.kind, k8s.resource_name(r.resource), name],
		),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s/sysctl=%s", [r.resource.kind, k8s.resource_name(r.resource), name]),
	}
}
