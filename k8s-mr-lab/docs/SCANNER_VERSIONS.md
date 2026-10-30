# Scanner versions and how they were verified

Chosen rule: **use the versions already installed in the project's Ubuntu 24.04 (WSL)** — no download, no upgrade.

| Item | Value | How it was checked |
|---|---|---|
| Trivy | 0.75.0 (`/usr/local/bin/trivy`) | `trivy --version` |
| Trivy checks bundle | `sha256:b591e9190cff4aa4e385b1a25bccfd9ecf178d3c77fd194e1410b7ce7e1df058` (downloaded 2026-10-28) | `~/.cache/trivy/policy/metadata.json`, run with `--skip-check-update` |
| Kubescape | v4.0.15 (`/usr/local/bin/kubescape`, build 16cfe102) | `kubescape version` |
| Kubescape artifacts | `~/.kubescape` (framework `allcontrols`, 290 controls) | sha256 recorded per run in `environment.lock.json` |
| Mode | local manifest scan for both (no cluster) | `config/scanners.yaml` |

Newer binaries exist elsewhere on the machine (`D:\Code\KLTN\Tools`: trivy 0.76.1, kubescape 4.0.16) and Kubescape
reports v4.0.17 as latest. They are deliberately **not** used; a different version means a different experiment
(re-capture golden files, re-run, compare) and is listed as a follow-up in `POC_REPORT_FOR_ADVISOR.md`.

## CLI facts verified with `--help` of the pinned binaries (not assumed)

* `trivy config --skip-check-update --skip-version-check --include-non-failures --format json --output F DIR` — exit code 0
  even with failures; PASS entries exist only with `--include-non-failures`.
* `kubescape scan framework allcontrols --keep-local --verbose --format json --output F --use-artifacts-from DIR TARGET` —
  `kubescape scan TARGET` alone fails offline (`framework from file not matching`), the framework must be named;
  `--verbose` is needed for passed resources to appear in the JSON.

## Rule facts verified by reading the pinned rule sources

* Trivy `KSV-0113` (`manage_namespace_secrets.rego`): matches `input.rules[_].resources[_] == "secrets"` with a verb in
  its list; **it never reads `apiGroups`**. Same for KSV-0048/0049/0050/0112 (no `apiGroups` token in the rego).
* Kubescape `C-0267` / `C-0272` (`workload-with-cluster-takeover-roles` / `-administrative-roles`): the rego joins
  `rolebinding.roleRef.name == role.metadata.name` and `rolebinding.roleRef.kind == role.kind` over **all** Roles in the
  input, with no namespace comparison.
