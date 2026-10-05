# Good first issues

Small, well-specified pieces of work for a first contribution. Each is self-contained, comes with the test to add, and needs no account, tenant, token or network access: tests build their own synthetic inputs. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first: standard library only, a test for every rule change, made-up names and documentation-only ids, key ids shown by their last four characters, plain language without em-dashes.

To claim one, open an issue with the title below (or comment on the existing one) and say you are working on it. Run `python3 -m pytest -q`, `ruff format --check . && ruff check .` and `python3 scripts/validate_plugin.py` before opening the pull request.

## 1. nhi-inventory: read Azure role assignments

**Labels:** good first issue, nhi-inventory, python

**Context.** Managed identities and service principals often hold Azure RBAC roles on subscriptions and resources, which the Graph exports do not show, so the inventory lists a managed identity with no assignments.

**Acceptance criteria.**
- An optional `azure-role-assignments.json` (the output of `az role assignment list --all --output json`) is read; each row whose `principalId` matches a service principal's object id adds an assignment of kind `azure-role` named `<roleDefinitionName> on <scope>`.
- The SKILL.md Inputs table gains the row with the command and the permission (Reader on the scope).
- A test with one matching and one unrelated assignment.

## 2. credential-expiry-radar: Azure Key Vault secrets and certificates

**Labels:** good first issue, credential-expiry-radar, python

**Context.** Agents often read their keys from Key Vault, and those secrets have their own expiry dates.

**Acceptance criteria.**
- An optional `azure-keyvault.json` holding the output of `az keyvault secret list --vault-name <vault>` and `az keyvault certificate list --vault-name <vault>` (a JSON list of both) is read; `attributes.expires` is the due date, the item `name` the identity, and a `tags.owner` value the owner.
- Disabled items (`attributes.enabled` false) are skipped; items without `expires` go to `no-expiry`.
- A test with an expired secret, a certificate due in 20 days and a disabled item.

## 3. entra-agent-id-review: list federated credential issuers and flag unexpected ones

**Labels:** good first issue, entra-agent-id-review, python

**Context.** Federated identity credentials let an outside workload (a GitHub Actions workflow, a Kubernetes service account) sign in as the app. An unexpected issuer is worth a look.

**Acceptance criteria.**
- `--trusted-issuer URL` (repeatable) lists the issuers the organisation expects, for example `https://token.actions.githubusercontent.com`.
- A federated credential whose `issuer` is not trusted raises `federated-issuer-untrusted` (MEDIUM) with the issuer and subject; without the option nothing changes.
- A test with one trusted and one untrusted issuer, and one with no option given.

## 4. connector-register: require a pinned version

**Labels:** good first issue, connector-register, python

**Context.** A register entry without a version cannot tell a reviewer which release was approved.

**Acceptance criteria.**
- `--require-version` raises `missing-version` for entries whose `version` is empty, and `unpinned-version` when it is `latest`, `*` or starts with `^` or `~`.
- Without the option, behaviour is unchanged.
- A test covering an exact version, `latest`, `^1.2.0` and an empty value.

## 5. agent-action-timeline: read the Azure activity log

**Labels:** good first issue, agent-action-timeline, python

**Context.** Managed identities and service principals act on Azure resources, and those actions are in the Azure activity log, not in Entra's audit log.

**Acceptance criteria.**
- `--azure-activity FILE` (repeatable) reads the output of `az monitor activity-log list --caller <appId or object id> --offset 7d --output json`.
- Each row becomes an event with time `eventTimestamp`, action `azure:<operationName.value>`, identity values from `caller` and `claims.appid`, target `resourceId`, and failed when `status.value` is `Failed`.
- The SKILL.md Inputs table gains the row; a test with one succeeded and one failed operation.

## 6. agent-recertification: route sheets to a delegate reviewer

**Labels:** good first issue, agent-recertification, python

**Context.** Some owners delegate the quarterly review (for example a team lead reviews for a whole team), and the sheets should go to the person who will actually answer.

**Acceptance criteria.**
- `--delegates CSV` with columns `owner,reviewer` routes every identity of `owner` to the sheet of `reviewer`, and the sheet names the original owner on each identity.
- An owner who left is still flagged `owner-left` even when a delegate exists.
- `tracking.csv` gains a `reviewer` column; a test with one delegated owner and one not delegated.
