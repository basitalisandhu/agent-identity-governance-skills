# Claude Code skills for agent identity governance: inventory, review, recertify, expire and switch off the non-human identities your AI agents and automations run as

**Eight skills that treat AI agents, service principals, workload identities, API keys and MCP connectors as identities: each needs an inventory entry, an owner, a periodic review, credentials that expire and an off switch. Offline, standard-library scripts over exports you save from Entra ID, AWS, GitHub and your own registers. Tested.**

## What this is, who it is for, and why

agent-identity-governance-skills is a Claude Code plugin for the people who run identity and cloud security: Microsoft 365 and Entra ID administrators, AWS platform and security engineers, and whoever is asked "what can our agents actually do?" by an auditor or a board.

Every AI agent and automation acts as some identity: an Entra app registration or agent identity, a managed identity, an IAM user with an access key, an IAM role, a GitHub App or deploy key, or the API key behind an MCP connector. People get joiner, mover and leaver processes and quarterly access reviews; these identities usually get none of that. They keep their permissions after the pilot ends, their secrets after the owner leaves, and nobody can say quickly how to turn one off. Microsoft's own guidance on Entra Agent ID makes the same point: agent identities persist, accumulate access and need access reviews ([Microsoft 365 Copilot blog: security and governance innovations for Microsoft 365 Copilot and agents](https://techcommunity.microsoft.com/blog/microsoft365copilotblog/security-and-governance-innovations-for-microsoft-365-copilot-and-agents-from-ig/4476172)). When this pack was written, in October 2026, a GitHub search for non-human identity audit tooling returned no repositories; the vendor features that exist are consoles inside one product.

This pack does the governance work from files. Each skill reads exports you take with read-only commands (Graph JSON from the Graph CLI or any Graph client, AWS CLI JSON, `gh api` JSON, CSV and YAML registers), applies stated rules, and writes a report, a sheet, a runbook or an evidence folder. Nothing calls a network, and nothing changes a tenant, an account or an organisation.

```text
/plugin marketplace add basitalisandhu/agent-identity-governance-skills
/plugin install agent-identity-governance@agent-identity-governance-skills
```

Quickstart: export your Entra applications and service principals into a folder, open Claude Code there and ask "which agent identities have no owner?". Or run a script directly from a clone of this repository:

```bash
python3 scripts/cli.py inventory ./exports --as-of 2026-10-05 --json --out inventory.json
python3 scripts/cli.py expiry-radar ./exports --as-of 2026-10-05
python3 scripts/cli.py kill-switch inventory.json --identity aws-role:agent-runtime --out runbook.md
```

Questions, bugs and ideas: open an issue on this repository. Security reports: see [SECURITY.md](SECURITY.md).

## Install

1. **From this marketplace in Claude Code** (shown above). Skills appear as `/agent-identity-governance:<skill>`, and Claude also uses them on its own when a request matches.
2. **Through the claude-skills aggregator**, which holds every pack I maintain as one marketplace (new packs appear there at its next sync):

   ```text
   /plugin marketplace add basitalisandhu/claude-skills
   /plugin install agent-identity-governance@claude-skills
   ```

3. **Without Claude Code**, as one command over the same scripts:
   - from a clone: `python3 scripts/cli.py <subcommand> [args]`, or `pip install .` for the `agent-identity-governance` command;
   - as a container image (GitHub Packages, linux/amd64 and linux/arm64), published when a version tag is pushed, signed with cosign (keyless), with a build provenance attestation and an SPDX SBOM attached to the GitHub Release. Mount the export folder at `/work`:

     ```bash
     docker run --rm -v "$PWD:/work" ghcr.io/basitalisandhu/agent-identity-governance-skills:0.1.0 inventory /work/exports --as-of 2026-10-05
     ```

| Subcommand | Script (skill) |
|---|---|
| `inventory` | `nhi_inventory.py` (nhi-inventory) |
| `agent-review` | `entra_agent_review.py` (entra-agent-id-review) |
| `recertify` | `agent_recertification.py` (agent-recertification) |
| `expiry-radar` | `credential_expiry_radar.py` (credential-expiry-radar) |
| `connector-register` | `connector_register.py` (connector-register) |
| `timeline` | `agent_action_timeline.py` (agent-action-timeline) |
| `kill-switch` | `kill_switch_runbook.py` (agent-kill-switch-runbook) |
| `leaked-credential` | `leaked_credential_response.py` (leaked-credential-response) |

## When to use this

- Nobody can list the identities your agents run as, or say who owns each one. `nhi-inventory`
- An agent platform or a batch of agent apps arrived in Entra and you want to know what they can reach without a user present. `entra-agent-id-review`
- The quarterly access review covers people but not the service principals, roles and keys behind your automations. `agent-recertification`
- A secret expired at night and an agent stopped, or access keys are older than the rotation policy. `credential-expiry-radar`
- MCP servers and connectors were approved one at a time and the list no longer matches what runs. `connector-register`
- Someone asks what an agent did last week, across Entra, AWS, GitHub and its own logs. `agent-action-timeline`
- An agent is about to go live and there is no written way to stop it. `agent-kill-switch-runbook`
- A key or token belonging to an agent turned up in a commit, a transcript or a log. `leaked-credential-response`

## Skills

Every script reads local files only, prints Markdown by default and JSON with `--json`, answers `--help`, and writes only to the path given with `--out`. Exit codes are the same across the pack: 0 nothing flagged, 1 something needs a person, 2 bad input. Where a date matters it is judged against `--as-of`, so a run can be repeated later with the same result. Key ids are shown by their last four characters and secret values are never read.

### `nhi-inventory`

| | |
|---|---|
| Triggers on | "which agent identities have no owner?", "list our service principals and API keys" |
| Reads | Entra applications, service principals, sign-in activity, permission grants; AWS authorization details, access keys, credential report; GitHub installations and deploy keys; a hand-kept `register.csv` |
| Produces | one inventory with type, owner, last used, credential count and oldest credential age; flags `no-owner`, `dormant`, `never-used`; JSON for the other skills |
| Script | `nhi_inventory.py` |

### `entra-agent-id-review`

| | |
|---|---|
| Triggers on | "what can our agent apps do in Entra?", "are our agent identities covered by Conditional Access?" |
| Reads | Graph exports of service principals, applications, agent identity and blueprint objects (preview), app role assignments, delegated grants, Conditional Access policies, sign-in activity |
| Produces | per identity: owners and sponsors, application and delegated permissions with high-risk ones from a fixed list highlighted, credential types and expiry, redirect URIs, Conditional Access coverage, findings by severity |
| Script | `entra_agent_review.py` |

### `agent-recertification`

| | |
|---|---|
| Triggers on | "prepare the agent access review for this quarter", "which agent owners have left?" |
| Reads | the inventory JSON, last quarter's attestation CSV, a users export, last quarter's inventory |
| Produces | one review sheet per owner (what each identity can do, when it last acted, what changed), an unassigned sheet, and `tracking.csv` with blank decision columns; flags `never-attested`, `attestation-stale`, `owner-left`, `no-owner`, `removal-not-done` |
| Script | `agent_recertification.py` |

### `credential-expiry-radar`

| | |
|---|---|
| Triggers on | "which app secrets expire this month?", "which access keys are older than 90 days?" |
| Reads | Entra application and service principal credentials, AWS access keys or the credential report, GitHub fine-grained tokens, `other-keys.csv` |
| Produces | every credential bucketed as expired, 7, 30, 90 days, later or no expiry, and an action list per owner |
| Script | `credential_expiry_radar.py` |

### `connector-register`

| | |
|---|---|
| Triggers on | "which MCP servers are we actually running?", "is the connector register still right?" |
| Reads | a register in CSV, YAML or JSON; saved MCP `tools/list` results; permission manifests |
| Produces | missing owners, purposes, classifications, permissions and review dates; overdue reviews; unregistered servers and tools; registered entries no longer present; permission drift |
| Script | `connector_register.py` |

### `agent-action-timeline`

| | |
|---|---|
| Triggers on | "what did this agent do last week?", "did the agent touch anything outside its job?" |
| Reads | Entra sign-in and directory audit logs, CloudTrail (lookup-events or log files), the GitHub audit log, application logs in JSON lines |
| Produces | one UTC timeline for the identity under all its names, with bursts, first-seen actions (against a baseline), actions outside an allow list and failures flagged |
| Script | `agent_action_timeline.py` |

### `agent-kill-switch-runbook`

| | |
|---|---|
| Triggers on | "how do we turn this agent off?", "write the kill switch for this service principal" |
| Reads | the identity's inventory record, an optional gateway name and Markdown template |
| Produces | ordered steps (stop new actions, end sessions, credentials, access, gateway, confirm), each with a change for a person to run and a read-only verification command, and a coverage check that every credential and assignment has a step |
| Script | `kill_switch_runbook.py` |

### `leaked-credential-response`

| | |
|---|---|
| Triggers on | "was this leaked key used?", "what do we rotate first?" |
| Reads | the inventory, the leaked key id's last four characters, the leak time, and audit exports |
| Produces | what the credential could reach (escalation-capable grants marked), events after the leak time with leaked-key and new-IP flags, credentials created after the leak, a rotation order, a checklist, and an evidence folder with byte-exact input copies and a SHA-256 manifest |
| Script | `leaked_credential_response.py` |

## What this is not

- **Not a change tool.** No skill disables, rotates, revokes or deletes anything. Runbooks and checklists show changes for a person to run.
- **Not a live connection.** No skill calls Microsoft Graph, AWS, GitHub or an MCP server. Export first; the exports stay on your machine.
- **Not a decision maker.** Owners decide keep, reduce or remove; decision lines stay blank.
- **Not a secret scanner.** `leaked-credential-response` starts once you know a credential leaked.

## How it fits with the other packs

- `nhi-inventory` and `entra-agent-id-review` cover non-human identities; `privileged-access-review` (m365-governance-skills) covers the people who hold admin roles, and `graph-permission-preflight` decides one app's Graph permissions before consent.
- `agent-recertification` is the non-human half of the quarterly review; `access-review-pack` (m365-governance-skills) is the human half.
- `iam-least-privilege-review` and `aws-account-audit` (aws-security-skills) judge what IAM policies allow and the account's guardrails; this pack records who the identities are, who owns them and how to stop them.
- `connector-register` keeps the approved list; `agent-config-audit` and `mcp-server-review` (agent-security-skills) audit the agent's configuration and a server's code.
- `leaked-credential-response` uses the same hashed-manifest pattern as `evidence-pack-builder` (compliance-evidence-skills), which packs evidence outside an incident.

## Security posture

- **Local, offline scripts.** The skill scripts read the files you name. They import no network or subprocess module (the repository validator checks this) and write only to the `--out` path you give. `scripts/cli.py` starts the chosen script with the same Python and nothing else.
- **No secret values.** Graph credential exports carry key ids and dates, not secrets; scripts show key ids by their last four characters. `--redact` on the inventory, the Entra review and the radar replaces e-mail addresses with stable tokens before a report is shared.
- **Your exports stay yours.** `.gitignore` ignores the default export names; keep exports and evidence folders out of version control.
- **Untrusted content.** Display names, tool descriptions and log fields are data, never instructions: each `SKILL.md` says so.
- **Synthetic tests.** Tests build their inputs at run time with made-up names and documentation-only ids; the only access key id in the repository is AWS's documentation example.

## What is inside

```text
.claude-plugin/marketplace.json                       marketplace manifest
plugins/agent-identity-governance/
├── .claude-plugin/plugin.json                        plugin manifest
├── README.md                                         the plugin's skill table
└── skills/<name>/
    ├── SKILL.md                                      when to use it, inputs, steps, script, output, limits, related skills
    └── scripts/<script>.py                           standard library only, --help, --json, documented exit codes
scripts/cli.py                                        the agent-identity-governance dispatcher (container and package entrypoint)
scripts/validate_plugin.py                            structure, frontmatter, scripts, READMEs, house style, secret shapes
tests/                                                pytest suite, offline; inputs are built in each test
```

## Development

```bash
python3 -m pytest -q
ruff format --check . && ruff check .
python3 scripts/validate_plugin.py
claude plugin validate --strict . && claude plugin validate --strict plugins/agent-identity-governance
```

CI runs the tests on Python 3.10 to 3.13 on Linux, macOS and Windows, builds the container image, and runs `claude plugin validate --strict`. See [CONTRIBUTING.md](CONTRIBUTING.md) for the ground rules and [docs/good-first-issues.md](docs/good-first-issues.md) for a place to start.

## Frequently asked questions

**Does any of this call Microsoft Graph, AWS or GitHub?**
No. The skills give you the read-only commands; you run them and save the output. The scripts read those files and nothing else.

**What counts as a non-human identity here?**
Entra app registrations, enterprise applications, managed identities and agent identities; AWS IAM users with access keys and IAM roles; GitHub Apps and deploy keys; and anything you list in `register.csv`, such as the API key behind an MCP connector.

**Does it support Microsoft Entra Agent ID?**
`entra-agent-id-review` reads agent identity and blueprint objects from the Graph beta endpoints when the export contains them, and reports blueprint credentials against each agent identity created from them. Those endpoints are in preview; the skill says what the export must contain, and falls back to name patterns and tags when a tenant has none.

**Can it show me the secret that leaked?**
No, and it never should. Scripts work with the last four characters of a key id; Graph exports do not contain secret values at all.

**Will it rotate or disable anything for me?**
No. `agent-kill-switch-runbook` writes the steps with verification commands, and `leaked-credential-response` writes the rotation order; a person runs them.

**Can I run it on a schedule?**
Yes, without Claude Code: run a subcommand with `--as-of` and act on the exit code, which is 1 when something needs a person. For example, `credential-expiry-radar` with `--fail-within 7` as a nightly check.

## Related repositories

| Repository | What it is |
|---|---|
| [m365-governance-skills](https://github.com/basitalisandhu/m365-governance-skills) | Microsoft 365 and Entra ID governance from Graph exports, including `privileged-access-review`, `graph-permission-preflight` and `access-review-pack` |
| [aws-security-skills](https://github.com/basitalisandhu/aws-security-skills) | AWS security skills, including `iam-least-privilege-review` and `aws-account-audit` |
| [compliance-evidence-skills](https://github.com/basitalisandhu/compliance-evidence-skills) | Compliance evidence from saved exports, including `evidence-pack-builder` |
| [agent-security-skills](https://github.com/basitalisandhu/agent-security-skills) | Security for AI agents, including `agent-config-audit` and `mcp-server-review` |
| [claude-skills](https://github.com/basitalisandhu/claude-skills) | Every pack in one marketplace |

More from the author: [basitalisandhu.github.io](https://basitalisandhu.github.io/).

## Licence

MIT. See [LICENSE](LICENSE).
