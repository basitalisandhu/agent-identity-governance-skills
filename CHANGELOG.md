# Changelog

All notable changes to this project are documented here. The format follows Keep a Changelog, and the project uses semantic versioning.

## [Unreleased]

## [0.1.0] - 2026-10-05

### Added

- Plugin marketplace `agent-identity-governance-skills` with one plugin, `agent-identity-governance`, whose eight skills each have a tested standard-library script that reads saved exports and never calls the network.
- `nhi-inventory`: `nhi_inventory.py` merges Entra application, service principal, sign-in activity, app role assignment and delegated grant exports, AWS authorization details, access keys and the credential report, GitHub installations and deploy keys, and a hand-kept `register.csv` into one inventory with type, owner, last used, credential count and oldest credential age; flags `no-owner`, `dormant` and `never-used`; writes JSON for the other skills; `--redact` tokenises e-mail addresses.
- `entra-agent-id-review`: `entra_agent_review.py` selects agent identities (agent identity objects, name pattern, tag, app id) and reports owners and sponsors, application and delegated permissions with a fixed high-risk list, credential expiry and lifetime including blueprint credentials, insecure and wildcard redirect URIs, Conditional Access coverage for workload identities and dormancy, with severities and `--fail-on`.
- `agent-recertification`: `agent_recertification.py` writes one review sheet per owner and `tracking.csv` from the inventory, last quarter's attestations, a users export and last quarter's inventory; flags `never-attested`, `attestation-stale`, `owner-left`, `no-owner` and `removal-not-done`, and lists changes since last quarter.
- `credential-expiry-radar`: `credential_expiry_radar.py` buckets Entra secrets and certificates, AWS access keys (due by age), GitHub fine-grained tokens and other keys as expired, 7, 30, 90 days, later or no expiry, with an action list per owner.
- `connector-register`: `connector_register.py` checks a CSV, YAML or JSON register of MCP servers, connectors and plugins for missing owner, purpose, classification, permissions and review date, overdue reviews and duplicates, and compares it with saved `tools/list` results and permission manifests for unregistered servers and tools, entries not present and permission drift.
- `agent-action-timeline`: `agent_action_timeline.py` reads Entra sign-in and directory audit logs, CloudTrail lookup-events output or log files, the GitHub audit log and JSON lines application logs, keeps one identity's events under all its names, orders them in UTC and flags bursts, first-seen actions against a baseline, actions outside an allow list and failures.
- `agent-kill-switch-runbook`: `kill_switch_runbook.py` writes the ordered switch-off runbook (stop new actions, end sessions, credentials, access, gateway, confirm) for Entra, AWS IAM user and role, GitHub App, deploy key and register identities, with read-only verification commands, an optional template, and a check that every credential and assignment in the inventory has a step.
- `leaked-credential-response`: `leaked_credential_response.py` reports a leaked credential's reach with escalation-capable grants marked, events after the leak time with leaked-key and new-source-IP flags, credentials created after the leak, a rotation order and a checklist, and writes an evidence folder with byte-exact input copies and a SHA-256 manifest.
- `scripts/cli.py`: the `agent-identity-governance <subcommand>` dispatcher (`inventory`, `agent-review`, `recertify`, `expiry-radar`, `connector-register`, `timeline`, `kill-switch`, `leaked-credential`), used by the container image and the Python package.
- `scripts/validate_plugin.py`, including a 600-character description limit, a quoted trigger phrase, the `Limits` and `Related skills` sections and a secret-shape check; a pytest suite whose inputs are built at run time; CI on Python 3.10 to 3.13 on Linux, macOS and Windows, a container build check and `claude plugin validate --strict`.
- `Dockerfile` and `publish-github-packages.yml`: on a `v*` tag, the image `ghcr.io/basitalisandhu/agent-identity-governance-skills` for linux/amd64 and linux/arm64 with an SPDX SBOM, a build provenance attestation and a keyless cosign signature.
- Tasks for new contributors in `docs/good-first-issues.md`.

[Unreleased]: https://github.com/basitalisandhu/agent-identity-governance-skills/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/basitalisandhu/agent-identity-governance-skills/releases/tag/v0.1.0
