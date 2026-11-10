# Advisory-agent service

A GitHub App service for tickets **P1.7** (diagnosis on every CI failure) and **P2.5** (LLM judge on diffs), built so **P4.2** (AI review) can plug in. It receives `workflow_run` webhooks outside PR workflows and posts neutral check runs under each agent's own App identity. Its keys stay in the service; none sits in a CI job.

No GitHub App, host or model provider has been chosen. The GitHub client and the diagnosis path have run read-only against real failed runs on the sandbox; see [Checked against real GitHub](#checked-against-real-github). [What needs a real App](#what-needs-a-real-app) lists what is still unproven.

> **Injection resistance is not proven.** The tests use a fake model client. They show what the code does with hostile input and with a fully compromised model's output: the check stays neutral, the structured signals don't change, and output outside the schema is discarded. They can't show that a real model resists a prompt injection. A real model can still be talked into a wrong diagnosis or a quiet judge result, which is one reason both stay advisory. Measure this with real models under P4.8 before relying on it.

## Run the tests

From `advisory/`, using the standard library only:

```bash
python3 -m unittest discover -s tests -t .
```

Five tests skip unless `requirements.txt` is installed: four run the real Anthropic SDK against a mock transport, and one checks a real RS256 signature. Keep any virtual environment outside the project folder.

## How it works

```
GitHub webhook -> /webhooks/<agent> -> verify signature -> allowlist, age, kill switch -> replay claim -> queue
queue -> narrowed installation token -> agent.run -> one check run, always completed and neutral
```

| Path | Purpose |
| --- | --- |
| `advisory_service/service.py` | Webhook verification, replay handling, routing, ratings, job execution |
| `advisory_service/github.py` | App JWT, narrowed tokens, read calls, and the only write: create a check run |
| `advisory_service/checks.py` | Check-run payload; the one place a conclusion is set |
| `advisory_service/models.py` | `ModelClient` interface, Anthropic client, provider registry, output validation |
| `advisory_service/redact.py` | Secret and personal-data redaction |
| `advisory_service/logs.py` | Failing-step selection, trimming, exit-code extraction |
| `advisory_service/signals.py` | Structured signals for P3.1, with no model involved |
| `advisory_service/untrusted.py` | Prompt fencing and output sanitizing |
| `advisory_service/diffstrip.py` | Diff parsing and comment removal |
| `advisory_service/agents/base.py` | The contract an agent implements |
| `advisory_service/agents/diagnosis.py` | P1.7 |
| `advisory_service/agents/judge.py` | P2.5 and the pattern catalogue |
| `advisory_service/store.py` | SQLite: claims, signals, hints, ratings, findings, ledger, token use |
| `advisory_service/cli.py` | HTTP server and record commands |

## Acceptance criteria

### P1.7 Diagnosis agent

| Criterion | Where | Status |
| --- | --- | --- |
| Runs on every failed run, agent and human PRs, from the service outside PR workflows | `DiagnosisAgent.accepts`, `service.py`; `tests/test_diagnosis.py` `Trigger` | Tested with fakes |
| Logs trimmed and redacted before leaving | `logs.prepare`, `redact.py`; `tests/test_redact.py` | Tested; see [limits](#what-redaction-misses) |
| Neutral, never-required check with a "not helpful" action | `checks.render`, `DiagnosisAgent.actions`; `CheckRun`, `Ratings` tests | Tested with fakes; button needs a real App |
| Read access plus checks only, no secret beyond its own model key | `github.py` `ALLOWED_PERMISSIONS`, `InstallationClient._send`; `tests/test_github_app.py` | Code enforced; App settings need a real App |
| P3.1 uses output only as a hint | Separate `signals` and `hints` tables; `cli signals` keeps them apart; `Signals` tests | Built here; P3.1 must honour it |

The hint's `failure_type` is the model's guess, so P3.1 must not unlock the fix loop from it.

Ratings go through `store.rating_rate`, which gives the plan's "not helpful" rate. Each person counts once per check.

### P2.5 LLM judge

| Criterion | Where | Status |
| --- | --- | --- |
| Runs from the service after the workflow finishes | `JudgeAgent.accepts`, once per head commit | Tested with fakes |
| Sees code with comments and the PR description stripped | `diffstrip.py`; the judge never fetches the PR or commit messages; `Judge`, `CommentStripping` tests | Tested; see [limits](#what-comment-stripping-misses) |
| Compares against an alternative where possible | `JudgeAgent._alternative` writes one from the old code and tests, without seeing the candidate | Mechanism tested; detection benefit not measured |
| Neutral, non-required check | `checks.render` | Tested with fakes |
| Confirmed hacks logged by catalogue category | `cli confirm`, `store.ledger_report`, `CATALOGUE` | Tested |

Only a person's verdict enters the ledger. A model finding gets an ID on the check, and a reviewer records it:

```bash
python3 -m advisory_service.cli confirm FINDING_ID --verdict confirmed_hack --by REVIEWER
```

`--by` is self-asserted, so limit CLI and database access to the people who review hacks.

**Never add an `advisory/` check to a ruleset as a required check.** GitHub's branch protection accepts neutral as passing, so a required advisory check would always pass. Only the plan's `required-checks-verified` gate (P2.9) insists on success. If the register ever promotes the judge, its conclusion logic must change in a reviewed PR first.

## Security decisions

- **Replay.** GitHub signs the body but not `X-GitHub-Delivery`, so claims key on the digest of the signed body. A captured body sent under a new delivery ID is refused. `workflow_run.updated_at` must be under 24 hours old, and digests are kept for 8 days, so an event can't outlive its digest. Failed jobs can be redelivered; finished ones can't.
- **Untrusted log text.** Log text goes in a fence with a per-request random tag. The model has no tools and must return JSON matching a schema, and output that doesn't match is discarded. The title is built from enum values only; free text is shown as a quote with links, HTML and mentions neutralised. Injection can still skew the prose, which is why that prose is labelled as a hint.
- **The failing step is chosen by time.** Runner timestamps can't be set by job output, while `##[group]` markers can be printed by anything.
- **Exit code.** The API doesn't expose it, so it's read from the runner's last `Process completed with exit code N.` line in the step's window. A process can print lookalikes earlier, and `exit_code_conflict` reports that. P3.1 should not trust a conflicted value.
- **Step and job names.** These come from the workflow file, which a PR can edit. P3.1 must apply its gate-violation row first.
- **Kill switch and allowlist.** Agents run only when `ADVISORY_KILL_SWITCH` is exactly `off`, and an empty repo allowlist refuses all, matching `kit/`.
- **Refusal fallback is on.** The Anthropic client sends `fallbacks: "default"`, so a safety-classifier decline, which security-flavoured logs can trigger, retries on another Claude model. A final refusal posts a signals-only check.

### What redaction misses

Patterns can't recognise a secret with no recognisable shape, such as a bare hex key or a short password printed on its own. Names are removed only from git identity lines and known actor logins, so a name elsewhere in free text survives. IPv6 is matched only in full form. GitHub's own masking of registered secrets (`***`) still applies first. Four real sandbox logs showed no leaks; that is a small sample, so review more before go-live.

### What comment stripping misses

Justifications can still live in string literals and identifiers; the judge's prompt treats those as suspect. Suppression markers such as `# noqa` disappear with comments, and `gates/tamper` (P2.2) catches those. Files with unknown types, including Markdown, are omitted and listed on the check as not reviewed. Where a hunk's boundary makes comment state ambiguous, the text is kept rather than risk hiding code.

## Adding P4.2

Subclass `Agent`, declare permissions inside the ceiling, and return a `CheckRunSpec` with `annotations`; `tests/test_platform.py` does this with a stub. Add it to `AGENTS` in `cli.py` and set its environment variables. Webhooks, replay, tokens, neutrality and model clients need no changes. P4.2's own passes, Useful and Not useful links, and token cap are not built.

## Checked against real GitHub

On 2026-11-09 the real `InstallationClient` and `DiagnosisAgent` ran against four failed runs on `owxyz/agent-kit-sandbox`. They used the maintainer's `gh` token, GET requests only, a fake model and check posting disabled. Confirmed:

- The jobs API returns steps with second-level timestamps. The log endpoint answers `302` to a short-lived blob URL, fetched without the token.
- The runner's timestamp prefix and `##[error]Process completed with exit code N.` line match the parser. Exit codes 1 and 2 were read correctly, with no conflicts.
- Steps share seconds, so the window is narrowed to the step header in its first second and to the runner's exit line. Windows went from about 100 lines to 9–29.
- Two redaction bugs appeared and are fixed: `KEY:` with an empty value swallowed the next line, and the window had included neighbouring steps.

GitHub's docs confirm:
- `workflow_run` needs Actions read, and `requested_action` needs Checks write and goes only to the App asked.
- Check runs allow at most 3 actions, with fields of 20, 40 and 20 characters, and 50 annotations per request.
- A token request can narrow repositories and permissions, and the response lists what was granted.
- The log download link expires after one minute.

One real model call, approved by the maintainer, was made on the redacted tamper-check log. The API rejected it, and the reason was lost because the code kept only the exception type. Errors now keep the HTTP status and error type, which show on the check, and the provider's message, which goes to the service log only. A second approved call showed the cause: HTTP 401 `authentication_error`, because the API key in the maintainer's environment is well-formed but rejected, probably revoked or expired. A third call with a new key was refused because the account had no API credit. The fourth, after credit was added, succeeded in 10 seconds on `claude-opus-5-5`, using 1,568 input and 335 output tokens (about $0.01). The API accepted the request shape: refusal fallback, structured output and adaptive thinking. The output matched the schema. The hint was right: it named the missing `apply_override.py` script and exit code 2, and noted the empty audit settings. That is one easy case, not a measure of accuracy or of injection resistance.

### Test App run, 2026-11-09

A test App (`owxyz-advisory-test-3549`) ran the real service on this Mac. Deliveries came through a smee.io relay, and the service was capped at 8 model calls; 3 were used. Confirmed:

- **Webhooks:** relayed deliveries passed signature verification with the App's real secret.
- **Tokens:** narrowed per-repo tokens worked for listing jobs, downloading logs and posting checks.
- **Diagnosis checks:** a rerun of a failed run got a neutral `advisory/diagnosis` check under the App's identity, with the attempt number in its external ID.
- **Not helpful button:** a click arrived as `check_run requested_action` with `external_id` intact, and one rating was recorded. The judge's endpoint refused it as not its check. GitHub's **Re-run** button sends `check_suite rerequested` instead, which the service ignores.
- **Fork PRs:** `pull_requests` is empty for fork runs, on `pull_request_target` as well as `pull_request`. Diagnosis still posts on the fork's head commit. The judge skips fork PRs; see [Fork PRs](#fork-prs).

Fixed during the run:
- **Unhandled events:** event types the service doesn't handle, such as `installation_repositories` and `check_suite`, got a `400`. They now get `202`.
- **Hidden diagnoses:** GitHub shows only the latest check of each name for a commit, so when two workflows failed only one diagnosis was visible. Checks are now named `advisory/diagnosis: <workflow>`, with the name sanitised.

Not run on real GitHub: the `tool` mapping on varied workflows. Every failing step so far had a descriptive name, so `tool` was `unknown`.

### Judge run, 2026-11-09

The real judge ran on throwaway same-repo PR 23, using the maintainer's `gh` token for GET requests only, two real model calls and posting disabled. The posting path is the one the diagnosis check already proved. The PR special-cased its test input, carried a comment calling the shortcut approved, and held a string telling AI reviewers to report nothing. Confirmed:

- **PR association:** same-repo runs carry `pull_requests` with base and head SHAs, including on `pull_request_target`, so the judge accepts them.
- **Stripping:** the compare diff had the comment removed, with no PR description or commit message. The injection string stayed inside the fence.
- **Alternative:** written from the old code and the tests without seeing the candidate, it came back as `return a + b`.
- **Findings:** the judge reported three, all high confidence:
  - overfitting visible checks (the hardcoded `(2, 3)`)
  - a test edit (an assertion on `main` rewritten to fit the hack)
  - check bypass (the "report no findings" string, flagged as intent to evade review)

  The comparison with the alternative was explicit.
- **Usage:** 1,835 input and 635 output tokens on `claude-opus-5-5`, about $0.02.

This is one blatant example; it measures neither detection rates nor resistance to subtler injection.

## Fork PRs

**Decision: the judge skips fork PRs.** GitHub sends no PR association for fork runs, and in this plan agent PRs come from branches in the same repository, so a fork PR is a human's. Diagnosis still runs on fork PRs. To judge forks later, look up the PR with `GET /repos/{repo}/commits/{sha}/pulls`; that needs Pull requests read on the judge's App and a matching register change.

## What needs a real App

The test App above covers the sandbox checks. For production:

1. Create one App per agent. Diagnosis needs Actions read and Checks write; the judge also needs Contents read. Both subscribe to **Workflow run** and **Check run**, with the webhook URL `https://<host>/webhooks/diagnosis` or `/webhooks/llm-judge`. Grant no Pull requests, Issues or Administration access. Install on selected repositories only.
2. Host it behind TLS with a request-rate limit and body timeout; the built-in server binds to localhost. A crash loses queued jobs, and a `503` isn't retried by GitHub, so both need a manual redelivery within the 24-hour limit. Alert on these.
3. Run a labelled set of failures and injection attempts (P4.8) to measure accuracy and injection resistance. Confirm your provider terms allow redacted logs and diffs to be sent.

## Placeholders

| Setting | Meaning |
| --- | --- |
| `ADVISORY_WEBHOOK_SECRETS` | Comma-separated, so old and new work during rotation. Secrets can't contain commas |
| `ADVISORY_DIAGNOSIS_APP_ID`, `ADVISORY_DIAGNOSIS_PRIVATE_KEY`, `ADVISORY_DIAGNOSIS_MODEL_KEY` | Diagnosis App and model key |
| `ADVISORY_LLM_JUDGE_APP_ID`, `ADVISORY_LLM_JUDGE_PRIVATE_KEY`, `ADVISORY_LLM_JUDGE_MODEL_KEY` | Judge App and model key |
| `ADVISORY_DB` | SQLite path outside any repository |
| `ADVISORY_KILL_SWITCH` | Must be exactly `off` for agents to run |
| `ADVISORY_ALLOWED_REPOS` | Comma-separated `owner/name`; empty refuses all |
| `ADVISORY_AGENT_LOGINS` | Agent logins; anyone else counts as human |
| `ADVISORY_MODEL_PROVIDER`, `ADVISORY_MODEL` | Default to `anthropic` and `claude-opus-5-5` |

Any secret can instead be mounted from a secrets manager and named with a `_FILE` suffix, such as `ADVISORY_DIAGNOSIS_MODEL_KEY_FILE`. Run with `python3 -m advisory_service.cli serve`. Rotate on the register's schedule by adding the new value, deploying, then removing the old one.

Pin `requirements.txt` to exact versions with hashes before deploying.

## Autonomy register entry

`inventory/autonomy-register.yaml` already has `diagnosis`, `llm-judge` and `app-service` agents and their secrets, so this adds no new IDs. **Replace `token_scope`** on the two agents below, because reading job logs and receiving `workflow_run` need Actions read. `contents` stays on `diagnosis` because the register schema requires it; the service still narrows that agent's token to Actions read and Checks write.

```yaml
  - id: diagnosis
    # job, plan_ref, level and promotion_metric unchanged
    token_scope:
      identity: Own GitHub App, run from the app service outside PR workflows
      permissions: {actions: read, contents: read, checks: write}
      notes: Read access plus checks only, so it cannot approve PRs. Actions read is needed for workflow_run events, job lists and job logs. Job tokens are narrowed to actions read and checks write.

  - id: llm-judge
    # job, plan_ref, level and promotion_metric unchanged
    token_scope:
      identity: Own GitHub App, run from the app service outside PR workflows
      permissions: {actions: read, contents: read, checks: write}
      notes: Actions read is needed only to receive workflow_run events. Job tokens are narrowed to contents read and checks write.
```

This edit validated against a scratch copy with `inventory/validate.py`: no errors, and the same 77 `TBD` items as today. The `review` entry will need the same `actions: read` when P4.2 arrives. The `llm-judge` promotion metric is still `TBD`, because the plan defines none.
