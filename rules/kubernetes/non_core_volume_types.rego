# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0028).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_non_core_volume_types

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0028",
	"name": "Non-core volume types used",
	"description": "According to pod security standard 'Volume types', non-core volume types must not be used.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-no-non-ephemeral-volumes",
	"languages": ["yaml"],
	"severity": "low",
	"level": "note",
	"kind": "iac",
	"cwe": ["CWE-732"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "volumes", "pss"],
}

_disallowed_volume_types := {
	"gcePersistentDisk",
	"awsElasticBlockStore",
	"gitRepo",
	"nfs",
	"iscsi",
	"glusterfs",
	"rbd",
	"flexVolume",
	"cinder",
	"cephFS",
	"flocker",
	"fc",
	"azureFile",
	"vsphereVolume",
	"quobyte",
	"azureDisk",
	"portworxVolume",
	"scaleIO",
	"storageos",
}

findings contains finding if {
	some r in k8s.resources_with_pod_templates
	some vol in object.get(r.pod_template.spec, "volumes", [])
	some vtype in _disallowed_volume_types
	_ := vol[vtype]
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"%s '%s' uses disallowed volume type '%s' on volume '%s'",
			[r.resource.kind, k8s.resource_name(r.resource), vtype, object.get(vol, "name", "<unnamed>")],
		),
		"artifact_uri": r.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": r.line,
		"snippet": sprintf("%s/%s/volume=%s", [r.resource.kind, k8s.resource_name(r.resource), object.get(vol, "name", "<unnamed>")]),
	}
}
