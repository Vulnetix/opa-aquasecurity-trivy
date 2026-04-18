# Adapted from https://github.com/aquasecurity/trivy-checks (KSV-0124).
# Ported to the Vulnetix Rego input schema (input.file_contents).

package vulnetix.rules.trivy_k8s_repo_ambiguous_prefix

import rego.v1

import data.vulnetix.trivy.k8s

metadata := {
	"id": "TRIVY-KSV-0124",
	"name": "Gatekeeper repo reference is ambiguously open-ended",
	"description": "A Gatekeeper policy that references image repositories for prefix-matching is using open-ended and ambiguous pattern, and can potentially match unintended repositories.",
	"help_uri": "https://avd.aquasec.com/misconfig/kubernetes-repo-ambiguous-prefix",
	"languages": ["yaml"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-20"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["kubernetes", "gatekeeper", "opa"],
}

_gatekeeper_allowed_repos(doc) if {
	doc.apiVersion == "constraints.gatekeeper.sh/v1beta1"
	doc.kind == "K8sAllowedRepos"
}

findings contains finding if {
	some d in k8s.documents
	_gatekeeper_allowed_repos(d.doc)
	some repo in object.get(object.get(d.doc.spec, "parameters", {}), "repos", [])
	not contains(repo, "/")
	not contains(repo, ":")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"K8sAllowedRepos '%s' has open-ended repo reference '%s'",
			[k8s.resource_name(d.doc), repo],
		),
		"artifact_uri": d.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": d.line,
		"snippet": repo,
	}
}

findings contains finding if {
	some d in k8s.documents
	_gatekeeper_allowed_repos(d.doc)
	some repo in object.get(object.get(d.doc.spec, "parameters", {}), "repos", [])
	parts := split(repo, "/")
	parts[0] == "docker.io"
	count(parts) <= 2
	finding := {
		"rule_id": metadata.id,
		"message": sprintf(
			"K8sAllowedRepos '%s' uses ambiguous 'docker.io' prefix for repo '%s'",
			[k8s.resource_name(d.doc), repo],
		),
		"artifact_uri": d.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": d.line,
		"snippet": repo,
	}
}
