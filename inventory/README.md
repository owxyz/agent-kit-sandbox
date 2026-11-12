# Agent inventory and autonomy register

Tooling for two Phase 0 tickets in `ci-cd-agents-tickets.csv`:

- **P0.1**: inventory every agent, its triggers, its token scopes and its credentials.
- **P0.13**: keep one register of each CI agent's autonomy level and long-lived secrets.

Everything runs offline on Python 3.9 or later with the standard library only.

| File | Purpose |
| --- | --- |
| `scan_workflows.py` | Scans checked-out repos for agent workflows |
| `manual-credentials.template.yaml` | Template for credentials a scan cannot see |
| `autonomy-register.yaml` | The register, prefilled with the plan's starting levels |
| `validate.py` | Validates the register and the manual inventory |
| `schemas/` | JSON Schemas for both files |
| `CODEOWNERS.example` | Lines that put the register under code-owner approval |
| `yamlite.py`, `schemalite.py` | Internal YAML reader and schema checker |

## Scan workflows

```bash
python3 inventory/scan_workflows.py path/to/repos
```

`path/to/repos` is a folder of checked-out repos, or a single repo.

| Option | Effect |
| --- | --- |
| `--format json` | Machine-readable report |
| `--output FILE` | Write the report to a file |
| `--all` | Also show workflows with no agent signal |
| `--agent-pattern REGEX` | Treat matching step `uses` or `run` text as an agent (for in-house agents; repeatable) |
| `--fail-on high` | Exit 1 if a reported workflow has a flag at this severity or above |
| `--credentials-seed FILE` | Write the credentials found as a manual-inventory file with `TBD` fields; refuses to overwrite |

A workflow counts as an agent workflow when any of these is true:

- A step uses a known agent action.
- A `run` step calls a known agent CLI.
- It references a model API key.
- It calls a local reusable workflow or composite action that does one of these.

| Flag | Severity | Meaning |
| --- | --- | --- |
| `broad-token-write-all` | critical | `permissions: write-all` |
| `broad-token-undeclared` | high | No `permissions` block, so the job gets the default token |
| `broad-token-sensitive-scope` | high | Write on a scope such as `checks`, `actions`, `packages` or `id-token` |
| `broad-token-contents-write` | medium | `contents: write` on `GITHUB_TOKEN` |
| `pull-request-target` | high, or critical if it checks out or fetches PR code | Critical also covers any checkout whose ref or repository can't be proven to be the base, and git commands that use an env variable carrying a PR ref. Includes workflows called from a `pull_request_target` workflow |
| `pat-style-secret` | high | Secret name looks like a personal access token |
| `secrets-inherit` | high | `secrets: inherit` passes every secret to the called workflow |
| `all-secrets-exposed` | critical | `toJSON(secrets)` |
| `dynamic-secret-reference` | high | Secret name computed at run time, so the list may be incomplete |
| `external-reusable-workflow` | medium | Calls a workflow in another repo that the scan cannot see |
| `local-action-not-read` | medium | A local action is missing, invalid or behind a symlink, so agents inside it are unknown |
| `parse-error` | high | The file could not be fully parsed; secrets and agent signals are found by text match |

### Limits

- Agent detection is a heuristic. Commands in full-line shell comments are ignored. An in-house agent with no recognizable model key in its workflow needs `--agent-pattern`.
- Every secret an agent workflow references goes on the list for the manual inventory, including those classed as `other`.
- Secret categories come from names, so a PAT named `DOCS_UPLOAD` is classed as `other`. Check that category by hand.
- The scan sees references, not real scopes. It cannot tell what a PAT can reach, or whether the org's default token is read-only.
- It reads the checked-out ref only. Workflows on other branches are not scanned.
- The YAML reader rejects constructs it does not support, such as tags and merge keys, and reports them as `parse-error`.

### Fetching repos and org credentials

An operator runs these read-only commands; this tooling never runs them. They need a `gh` login with read access. None of them returns a secret value.

List and clone repos, then scan the folder:

```bash
gh repo list YOUR_ORG --limit 1000 --no-archived --json nameWithOwner --jq '.[].nameWithOwner' > repos.txt
```

```bash
while read -r r; do gh repo clone "$r" "repos/${r#*/}" -- --depth 1; done < repos.txt
```

Secret names at org, repo and environment level:

```bash
gh api --paginate /orgs/YOUR_ORG/actions/secrets --jq '.secrets[].name'
```

```bash
gh api --paginate /repos/YOUR_ORG/REPO/actions/secrets --jq '.secrets[].name'
```

```bash
gh api --paginate /repos/YOUR_ORG/REPO/environments/ENVIRONMENT/secrets --jq '.secrets[].name'
```

Default workflow token setting:

```bash
gh api /orgs/YOUR_ORG/actions/permissions/workflow
```

Deploy keys on a repo:

```bash
gh api --paginate /repos/YOUR_ORG/REPO/keys --jq '.[] | {id, title, read_only, created_at}'
```

Installed GitHub Apps and their permissions:

```bash
gh api --paginate /orgs/YOUR_ORG/installations --jq '.installations[] | {app_slug, permissions, repository_selection}'
```

Fine-grained PATs approved for the org (GitHub restricts this endpoint to GitHub App tokens):

```bash
gh api --paginate /orgs/YOUR_ORG/personal-access-tokens
```

Classic PATs authorized for SSO (SAML orgs only):

```bash
gh api --paginate /orgs/YOUR_ORG/credential-authorizations
```

Classic PATs outside SAML cannot be listed. Ask each team, and check agent config and bot accounts. Model API keys are listed in each provider's console.

## Manual credential inventory

1. Copy `manual-credentials.template.yaml` to `manual-credentials.yaml`, or start from `--credentials-seed`.
2. Add every PAT, deploy key, GitHub App private key and model API key, whether or not a workflow uses it.
3. Set `broad` after checking the real scope. A broad credential needs an owner and a removal date.
4. Have security review the file and record it under `security_review`.

```bash
python3 inventory/validate.py credentials manual-credentials.yaml
```

Do not commit real values. The validator rejects values shaped like GitHub tokens, `sk-` keys, AWS access key IDs and private keys.

## Autonomy register

```bash
python3 inventory/validate.py register
```

| Exit code | Meaning |
| --- | --- |
| 0 | Valid and complete. Due-soon warnings do not change this. |
| 1 | Schema or rule error, or a rotation or removal date is overdue |
| 2 | File missing or not parseable |
| 3 | Valid, but `TBD` values remain |

`--allow-incomplete` turns exit 3 into 0 during rollout. `--today YYYY-MM-DD` checks dates against another day, and `--format json` gives machine-readable output.

Rules beyond the schema:

- No agent holds admin or workflow scope (P0.2).
- An Advise agent may write checks and nothing else.
- Every agent has a GitHub App key and a model key entry, and the app service has a webhook secret entry.
- A secret's location cannot be CI secrets or variables.
- `rotation_date` is at most `rotation_days` after `last_rotated` (default 90), and `alert_date` falls before it.
- A rotation within `due_soon_days` (default 14) or past its alert date is reported as due soon.
- A value shaped like a credential is an error.

Dates are `TBD` in the prefilled file because the keys do not exist yet. Once `last_rotated` is set, the validator suggests the 90-day date, then the alert date.

Values to confirm:

- The 14-day alert and due-soon windows are proposals; the plan only asks for an alert before the due date.
- Token scopes for `broad-repair` and `dependency-repair` are derived from P3.3 and P3.4.
- `TBD` means someone still has to decide. The LLM judge's metric stays `TBD` until P4.8 has collected confirmed reward hacks, because any number now would be invented.
- Suggested patches have a written "no target yet" value, because the plan deliberately tracks them only until a baseline exists.
- The narrow-repair target is a proposal. The plan reports fix rate by failure type with no overall target, so "promotion" there means adding a failure type.
- P3.4 does not say how a person learns of a dependency patch. If the agent must comment on the PR, its `pull_requests` scope must become `write`.

### Changing the register

Code owners approve every change. To enforce that, copy `CODEOWNERS.example` into the hosting repo and require code-owner review on the default branch.

1. Open a PR that edits `autonomy-register.yaml`.
2. Run the validator in CI on that PR. Use `--allow-incomplete` until the `TBD` values are gone.
3. To raise a level, link the measured metric in the PR and show that it meets the entry's target.
4. A code owner approves and merges.

**Model, prompt or tool changes.** Until the eval gate (P4.8) exists, any change to an agent's model, prompt or tools needs code-owner approval and a side-by-side check on recent cases. Attach the comparison to the PR, including how often the agent games tests.

**Rotating a key.** Add the new key, deploy it, then delete the old one. A GitHub App can hold more than one key at a time. Then update `last_rotated`, `rotation_date` and `alert_date`, and close any open rotation issue.

**Rotating the webhook secret.** Confirm this against GitHub's current docs: a GitHub App is expected to have one webhook secret at a time, so there is no add-then-delete. Deploy the app service so it accepts both the old and new secret, change the secret in the app settings, then deploy again without the old one.

**Staggering rotations.** Spread first rotation dates when keys are created, so all the secrets don't come due on the same day.

**Rotation alerts.** `templates/register-check.yml` opens one issue per secret when it comes due, and another if it goes overdue. Write `owner` as `@user` or `@org/team` so the issue notifies them.

**Retiring an agent.** Uninstall its app, revoke its keys, and remove its entries in the same PR.

## Needs a real org

These ticket criteria cannot be met or tested from this folder.

| Ticket | Remaining work |
| --- | --- |
| P0.1 | Run `fetch_inventory.sh ORG OUTPUT_DIR` (or the `gh` commands above), then scan `OUTPUT_DIR/repos` |
| P0.1 | Fill the manual inventory with real credentials, owners and removal dates |
| P0.1 | Get the security review |
| P0.13 | Name real owners and secrets-manager locations, and set rotation dates once keys exist |
| P0.13 | Enforce code-owner approval with a real CODEOWNERS file and ruleset |
| P0.13 | Turn on secret scanning with push protection |
| P0.13 | Add an alert on unusual model API spend |
| P0.13 | Install `templates/register-check.yml`, pinning `actions/checkout` to a SHA. It validates PRs and opens an issue daily when a rotation is overdue or due soon |
| P0.13 | Run side-by-side checks on real agent changes until P4.8 exists, using `templates/agent-change-pull-request-template.md` |
| P0.13 | List the real coding agents in place of `coding-agent-tbd` after P0.2 |

## Tests

```bash
python3 -m unittest discover -s inventory/tests
```

Fixture workflows are in `tests/fixtures/repos/`. They are fake and contain no real credentials.
