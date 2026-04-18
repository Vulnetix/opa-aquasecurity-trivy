# opa-aquasecurity-trivy

Vulnetix-compatible OPA/Rego rules for Dockerfile and Kubernetes manifest security, adapted from the intent of [Aqua Security trivy-checks](https://github.com/aquasecurity/trivy-checks).

## Clean-room approach

These rules were produced using a **clean-room** methodology:

1. The **intent** of each upstream trivy-checks rule was studied — what misconfiguration it detects, why it matters, and what remediation it recommends.
2. Detection logic was then **written from scratch** against the Vulnetix `input.file_contents` schema.
3. **No upstream Rego code was copied.** The original trivy-checks rules operate on a fundamentally different input schema (parsed JSON structures produced by Trivy's Go loader), so they cannot be used verbatim with Vulnetix.
4. The helper libraries (`rules/_lib/docker.rego` and `rules/_lib/k8s.rego`) are original implementations that parse raw file text using regex and `yaml.unmarshal` — they are not derived from Trivy's Go-side parsers.

The result is a set of rules that match the **security intent** of the upstream checks while being natively compatible with the Vulnetix CLI's `--rule` mechanism.

## Coverage

| Category | Rules | ID prefix | Description |
|----------|-------|-----------|-------------|
| Dockerfile | 28 | `TRIVY-DS-*` | Best practices: ADD vs COPY, root user, package pinning, HEALTHCHECK, secrets, etc. |
| Kubernetes | 79 | `TRIVY-KSV-*` | Pod/container security: capabilities, privileged, hostPath, resource limits, seccomp/AppArmor, RBAC, PSS-aligned controls. |

**Not included:** The 90 `KCV-*` CIS Kubernetes benchmark rules from the upstream repository. Those rules operate on live cluster `NodeInfo` and apiserver runtime arguments and cannot be expressed against local manifest files.

## Layout

```
opa-aquasecurity-trivy/
├── LICENSE                         ← Apache 2.0
├── README.md
└── rules/
    ├── _lib/
    │   ├── docker.rego             # package vulnetix.trivy.docker
    │   └── k8s.rego                # package vulnetix.trivy.k8s
    ├── docker/<rule>.rego          # package vulnetix.rules.trivy_docker_*
    └── kubernetes/<rule>.rego      # package vulnetix.rules.trivy_k8s_*
```

## Usage

```bash
# Use alongside built-in rules
vulnetix scan --rule Vulnetix/opa-aquasecurity-trivy

# Use only these rules (disable built-ins)
vulnetix scan --rule Vulnetix/opa-aquasecurity-trivy --disable-default-rules

# Combine with other custom rule repos
vulnetix scan \
  --rule Vulnetix/opa-aquasecurity-trivy \
  --rule myorg/additional-rules
```

## Input schema

Rules operate on Vulnetix's `input.file_contents` map (file path → raw file text):

```json
{
  "file_contents": {
    "Dockerfile": "FROM ubuntu:22.04\n...",
    "deploy.yaml": "apiVersion: apps/v1\n..."
  }
}
```

- Dockerfile rules parse instructions via the `docker` helper library (regex-based)
- Kubernetes rules parse manifests via the `k8s` helper library (`yaml.unmarshal` with multi-document splitting)
- No cluster access, no cloud APIs, no registry fetches — purely local file scanning

## Attribution

The security checks in this repository are inspired by [Aqua Security trivy-checks](https://github.com/aquasecurity/trivy-checks), which is licensed under the [MIT License](https://github.com/aquasecurity/trivy-checks/blob/main/LICENSE).

Copyright (c) 2024 Aqua Security. The upstream trivy-checks project is the original source of the misconfiguration categories and security rationale that these rules are based on.

This repository is licensed under [Apache 2.0](LICENSE).
