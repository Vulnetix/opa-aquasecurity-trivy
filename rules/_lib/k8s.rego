# Helper package — not a rule.
# Parses Kubernetes YAML manifests from input.file_contents into resource docs.
# Used by aquasecurity-trivy-checks Kubernetes ports.

package vulnetix.trivy.k8s

import rego.v1

is_yaml(path) if endswith(lower(path), ".yaml")
is_yaml(path) if endswith(lower(path), ".yml")

# All k8s documents across all YAML files in input.file_contents.
# Each entry: {path, doc, line} — line is the 1-based offset of the doc in the file.
documents := [d |
	some path, content in input.file_contents
	is_yaml(path)
	some entry in _split_docs_with_offsets(content)
	doc := yaml.unmarshal(entry.body)
	is_object(doc)
	doc.apiVersion
	doc.kind
	d := {"path": path, "doc": doc, "line": entry.line}
]

# Split multi-document YAML and return {body, line} entries.
_split_docs_with_offsets(content) := out if {
	contains(content, "\n---\n")
	parts := split(content, "\n---\n")
	out := [{"body": p, "line": _doc_start_line(content, i, parts)} |
		some i, p in parts
		p != ""
	]
}

_split_docs_with_offsets(content) := [{"body": content, "line": 1}] if {
	not contains(content, "\n---\n")
}

# Count lines in all preceding segments (plus their separators) to get the
# 1-based line where the i-th doc begins.
_doc_start_line(_, 0, _) := 1

_doc_start_line(_, i, parts) := line if {
	i > 0
	prior_lines := [c |
		some j in numbers.range(0, i - 1)
		c := count(split(parts[j], "\n"))
	]
	# each `---` separator consumes 1 line
	line := sum(prior_lines) + i + 1
}

# Resources of a particular kind.
resources(kind) := [d |
	some d in documents
	d.doc.kind == kind
]

# Documents that contain a pod template.
pod_template_kinds := {
	"Deployment",
	"StatefulSet",
	"DaemonSet",
	"Job",
	"CronJob",
	"ReplicaSet",
	"ReplicationController",
	"Pod",
	"DeploymentConfig",
}

resources_with_pod_templates := [r |
	some d in documents
	pod_template_kinds[d.doc.kind]
	pt := _pod_template(d.doc)
	r := {"path": d.path, "resource": d.doc, "pod_template": pt, "line": d.line}
]

_pod_template(doc) := doc if doc.kind == "Pod"

_pod_template(doc) := doc.spec.template if {
	doc.kind != "Pod"
	doc.kind != "CronJob"
	doc.spec.template
}

_pod_template(doc) := doc.spec.jobTemplate.spec.template if {
	doc.kind == "CronJob"
}

# Containers (spec + initContainers) from a pod template.
containers(template) := array.concat(
	object.get(template.spec, "containers", []),
	object.get(template.spec, "initContainers", []),
)

# All container entries across every pod-template-bearing resource.
# Each entry: {path, resource, container, line, pod_template}
all_containers := [c |
	some obj in resources_with_pod_templates
	some ctn in containers(obj.pod_template)
	c := {
		"path": obj.path,
		"resource": obj.resource,
		"container": ctn,
		"line": obj.line,
		"pod_template": obj.pod_template,
	}
]

# Pod spec for any resource — pod template spec for workload kinds, or .spec for Pod.
pod_spec(doc) := doc.spec if doc.kind == "Pod"

pod_spec(doc) := doc.spec.template.spec if {
	doc.kind != "Pod"
	doc.kind != "CronJob"
	doc.spec.template.spec
}

pod_spec(doc) := doc.spec.jobTemplate.spec.template.spec if {
	doc.kind == "CronJob"
}

# Role-like resources (Role and ClusterRole).
roles := [d |
	some d in documents
	d.doc.kind in {"Role", "ClusterRole"}
]

role_bindings := [d |
	some d in documents
	d.doc.kind in {"RoleBinding", "ClusterRoleBinding"}
]

service_accounts := [d |
	some d in documents
	d.doc.kind == "ServiceAccount"
]

# All (role, rule) pairs across Role/ClusterRole.
role_rules := [r |
	some d in roles
	some rule in object.get(d.doc, "rules", [])
	r := {"path": d.path, "role": d.doc, "rule": rule, "line": d.line}
]

# Role permits wildcard on any of: verbs, resources, apiGroups.
rule_has_wildcard_verb(rule) if "*" in object.get(rule, "verbs", [])

rule_has_wildcard_resource(rule) if "*" in object.get(rule, "resources", [])

rule_has_wildcard_apigroup(rule) if "*" in object.get(rule, "apiGroups", [])

# A rule granting a specific verb/resource combo.
rule_permits(rule, verb, resource) if {
	_verb_matches(rule, verb)
	_resource_matches(rule, resource)
}

_verb_matches(rule, verb) if {
	verbs := object.get(rule, "verbs", [])
	some v in verbs
	v in {verb, "*"}
}

_resource_matches(rule, resource) if {
	resources := object.get(rule, "resources", [])
	some r in resources
	r in {resource, "*"}
}

# Role/ClusterRole bindings that reference a given subject kind+name.
binding_has_subject(binding_doc, kind, name) if {
	some sub in object.get(binding_doc, "subjects", [])
	sub.kind == kind
	sub.name == name
}

# Does a binding reference any system: group?
binding_has_system_group(binding_doc, group_name) if {
	some sub in object.get(binding_doc, "subjects", [])
	sub.kind == "Group"
	sub.name == group_name
}

namespaced_kinds := {
	"ConfigMap",
	"CronJob",
	"DaemonSet",
	"Deployment",
	"Ingress",
	"Job",
	"NetworkPolicy",
	"Pod",
	"ReplicaSet",
	"ReplicationController",
	"Role",
	"RoleBinding",
	"Secret",
	"Service",
	"ServiceAccount",
	"StatefulSet",
}

namespaced_resources := [d |
	some d in documents
	namespaced_kinds[d.doc.kind]
]

# Security context accessors.
container_security_context(container) := object.get(container, "securityContext", {})

pod_security_context(pod_template) := object.get(pod_template.spec, "securityContext", {})

added_capabilities(container) := object.get(
	object.get(container_security_context(container), "capabilities", {}),
	"add",
	[],
)

dropped_capabilities(container) := object.get(
	object.get(container_security_context(container), "capabilities", {}),
	"drop",
	[],
)

# True when a container field is boolean true (after walking securityContext).
sc_bool_true(container, field) if {
	sc := container_security_context(container)
	sc[field] == true
}

pod_sc_bool_true(pod_template, field) if {
	sc := pod_security_context(pod_template)
	sc[field] == true
}

# Generic default: apiVersion/namespace/name getters.
resource_name(doc) := object.get(object.get(doc, "metadata", {}), "name", "<unnamed>")

resource_namespace(doc) := object.get(object.get(doc, "metadata", {}), "namespace", "default")
