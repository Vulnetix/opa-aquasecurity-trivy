# Adapted from https://github.com/aquasecurity/trivy-checks (DS-0031).
# Ported to the Vulnetix Rego input schema (input.file_contents).
#
# Heuristic-only: real Trivy implementation depends on external secret
# scanning results. This port flags ENV/ARG assignments whose name matches
# well-known credential-style tokens (password, token, secret, api_key, etc.)
# as well as hard-coded AWS/GH/cloud provider credential env names. It does
# not inspect values nor runtime secret mounts.

package vulnetix.rules.trivy_docker_leaked_secrets

import rego.v1

import data.vulnetix.trivy.docker

metadata := {
	"id": "TRIVY-DS-0031",
	"name": "Secrets passed via `build-args` or envs or copied secret files",
	"description": "Passing secrets via `build-args` or envs or copying secret files can leak them out. Use secret mount if secrets are needed during image build.",
	"help_uri": "https://avd.aquasec.com/misconfig/docker-do-not-pass-secrets",
	"languages": ["dockerfile"],
	"severity": "critical",
	"level": "error",
	"kind": "iac",
	"cwe": ["CWE-798", "CWE-538"],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["dockerfile", "secrets", "credentials"],
}

_known_secret_envs := {
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AZURE_CLIENT_ID",
	"AZURE_CLIENT_SECRET",
	"GITHUB_TOKEN",
	"GH_TOKEN",
	"GH_ENTERPRISE_TOKEN",
	"GITHUB_ENTERPRISE_TOKEN",
	"OPENAI_API_KEY",
	"HF_TOKEN",
	"DIGITALOCEAN_ACCESS_TOKEN",
	"DOCKERHUB_PASSWORD",
	"FIREBASE_TOKEN",
	"CI_DEPLOY_PASSWORD",
	"GOOGLE_API_KEY",
	"LANGSMITH_API_KEY",
	"LANGCHAIN_API_KEY",
	"HEROKU_API_KEY",
}

_secret_file_envs := {
	"AWS_CONFIG_FILE",
	"HF_TOKEN_PATH",
	"GOOGLE_APPLICATION_CREDENTIALS",
}

_secret_name_pattern := `(?i)(?:^|_)(apikey|auth|credential|credentials|key|password|pword|passwd|secret|token|usr|psw)(?:_|$)`

findings contains finding if {
	some f in docker.dockerfiles
	some inst in docker.instructions(f.content)
	inst.cmd == "env"
	name := _first_assignment_name(inst.value)
	_is_secret_name(name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Possible exposure of secret env %q in ENV", [name]),
		"artifact_uri": f.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": inst.line,
		"snippet": inst.original,
	}
}

findings contains finding if {
	some f in docker.dockerfiles
	some inst in docker.instructions(f.content)
	inst.cmd == "arg"
	name := _first_assignment_name(inst.value)
	_is_secret_name(name)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Possible exposure of secret env %q in ARG", [name]),
		"artifact_uri": f.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": inst.line,
		"snippet": inst.original,
	}
}

# RUN that configures cloud credentials inline without --mount=type=secret.
findings contains finding if {
	some run in docker.run_cmds
	_uses_cred_setup(run.value)
	not _has_secret_mount(run.original)
	finding := {
		"rule_id": metadata.id,
		"message": "Possible exposure of secret in RUN (credential setup without --mount=type=secret)",
		"artifact_uri": run.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": run.line,
		"snippet": run.original,
	}
}

_first_assignment_name(value) := name if {
	trimmed := trim_space(value)
	parts := regex.split(`\s+`, trimmed)
	count(parts) > 0
	head := parts[0]
	name := split(head, "=")[0]
}

_is_secret_name(name) if name in _known_secret_envs

_is_secret_name(name) if name in _secret_file_envs

_is_secret_name(name) if regex.match(_secret_name_pattern, name)

# The upstream excludes "public" as an allowed token; mirror that filter.
_is_secret_name(name) if {
	regex.match(_secret_name_pattern, name)
	not regex.match(`(?i)(?:^|_)public(?:_|$)`, name)
}

_uses_cred_setup(value) if regex.match(`aws configure set aws_access_key_id`, value)

_uses_cred_setup(value) if regex.match(`aws configure set aws_secret_access_key`, value)

_uses_cred_setup(value) if regex.match(`gcloud auth activate-service-account`, value)

_uses_cred_setup(value) if regex.match(`az login.*(?:-p|--password|--federated-token)\s`, value)

_uses_cred_setup(value) if regex.match(`doctl auth init.*(?:-t|--access-token)\s`, value)

_has_secret_mount(original) if contains(original, "--mount=type=secret")
