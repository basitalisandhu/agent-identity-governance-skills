# Changelog

All notable changes to this project are documented here. The format follows Keep a Changelog, and the project uses semantic versioning.

## [Unreleased]

## [0.3.0] - 2026-10-20

### Added

- `agent-audit-log-integrity`: `audit_chain.py` with three subcommands. `seal` adds `{"_chain": {"seq", "prev", "hash", "alg"}}` to every line of an agent audit log in JSON lines, where the hash is SHA-256, or HMAC-SHA256 with `--key-file`, over the sequence number, the previous hash and the line's canonical JSON, and prints the head to store outside the log writer's reach (`--start-seq` continues a chain). `verify` reports `hash-mismatch`, `seq-gap`, `prev-mismatch`, `seq-backwards`, `duplicate-seq`, `unsealed-line`, `unparseable-line`, `starts-mid-chain`, `truncated`, `head-mismatch`, `time-backwards`, `key-needed` and `mixed-algorithms`, with `appended` as information. `coverage` compares the logged action ids with a Claude Code session log's `tool_use` ids or an id list and lists actions never recorded. Exit 0, 1, 2. 13 tests, bundled examples in `examples/audit/` (a sealed log, a tampered copy, its head and a session), subcommand `audit-chain`, and a container CI sample that seals, edits and verifies a log.

## [0.2.0] - 2026-10-18

### Added

- Bundled synthetic examples in `plugins/agent-identity-governance/examples/` (Entra apps and service principals, an Entra Agent ID blueprint with two agent identities and an inherited Graph permission, an IAM user and role, a register, attestations, a users export, a connector register with tool listings and a manifest, a CloudTrail sample and an allow list). Every SKILL.md starts its Script section with the run on them, and `tests/test_examples.py` keeps those runs and their exit codes true. Before this, a new user had nothing to run a skill on without exporting from a tenant first.
- Entra Agent ID across the pack. `nhi-inventory` reads `entra-agent-blueprints.json` and `entra-agent-identities.json` (Graph v1.0 `applications/microsoft.graph.agentIdentityBlueprint` and `servicePrincipals/microsoft.graph.agentIdentity`): blueprints carry the credentials and list the agent identities that depend on them, agent identities take their sponsors (or the blueprint's) as owners, a blueprint is in use while any of its agents is, and the report has a section per blueprint. `entra-agent-id-review` reviews the blueprint principal with the blueprint's credentials and sponsors, lists permissions granted to it as inherited on every agent identity (a high-risk one is HIGH on each) and names the blueprint's sponsors when an agent has none. `credential-expiry-radar` reads blueprint credentials, says how many agent identities use each, and counts a blueprint listed in two exports once. `agent-kill-switch-runbook` disables an agent identity with `PATCH /servicePrincipals/{id}/microsoft.graph.agentIdentity` and leaves the shared blueprint credentials alone, and a blueprint runbook first lists every agent it would stop.

### Fixed

- `agent-recertification`: two owners whose addresses slug to the same file name (`sam@example.com`, `sam.example.com`) wrote one sheet over the other; later ones are numbered. A users export saved as a list of pages made every owner count as left, and an export with no `userPrincipalName` or `mail` now exits 2 instead. An attestation dated after `--as-of` counted as fresh; it is now stale. A CSV inventory row with an empty or repeated id, `--max-age 0` and an `--out` that is a file exit 2.
- `connector-register`: listing and manifest files now match register names without regard to case, and `/` in a name is written `__` in the file name (`@acme/tickets-mcp`), so scoped npm names can be checked at all; duplicate names that differ only in case or spaces are reported; a review date saved with a time part is read as a date; an empty `--classifications` exits 2.
- `credential-expiry-radar`: a credential entry that is not an object no longer crashes the run; owners include sponsors.
- Every script that takes `--out FILE` exits 2 with a message when the file cannot be written, instead of a traceback.
- Each SKILL.md says where the script is when the skill folder is copied without the plugin system (closes #7).

### Changed

- `nhi-inventory`, `credential-expiry-radar` and `entra-agent-id-review` descriptions mention Agent ID and say they are not the human access review pack or a tenant-wide baseline, so prompts meant for `access-review-pack` and `entra-posture-review` do not land here.
- Version 0.2.0 in the marketplace, plugin manifest, `pyproject.toml`, the CLI and the container example.

## [0.1.1] - 2026-10-05

### Changed

- The phrase a user would type in each of the eight skill descriptions is now in double quotes instead of single quotes, so description linters and skill listings recognise it as a trigger phrase.
- `scripts/validate_plugin.py` now requires a double-quoted trigger phrase of 2 to 8 words in every description (the single-quote rule is gone); the description rules moved into `description_problems()`, with tests.

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
