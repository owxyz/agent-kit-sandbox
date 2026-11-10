# Concurrency, cost limits and developer onboarding

Tickets **P1.5** and **P1.6**. Everything here has been tested locally against a fake GitHub API and a real metrics store. The patched pre-flight was also proven on a throwaway private repo; see [What needs a real repo](#what-needs-a-real-repo). **Nothing in `kit/` has been changed and no pilot repo has it.** [INTEGRATION.md](INTEGRATION.md) is the step that connects it.

It needs Python 3.9 or later and has no third-party dependencies at run time.

## What's here

| Path | Purpose |
| --- | --- |
| `scripts/check_limits.py` | The check: exit 0 allows, 1 is a limit reached, 2 is could not decide |
| `scripts/limits_config.py`, `limits_store.py`, `limits_github.py` | Config validation, read-only store access, read-only GitHub client |
| `config/limits.json` | Limits. Refuses to run until the budget is set |
| `integration/agent-preflight.patch` | The exact pre-flight edit |
| `INTEGRATION.md` | Install steps |
| `docs/pilot-team-guide.md` | Pilot-team docs on gates, overrides and handoffs |
| `docs/announcement-draft.md`, `docs/office-hours-agenda.md` | Drafts. Nothing has been sent or scheduled |

## Acceptance criteria

**Status:** *Built* means implemented and covered by tests here. *Needs repo* means it can only be proven on GitHub. *Process* means a person has to do it.

| Ticket | Criterion | File | Status |
| --- | --- | --- | --- |
| P1.5 | A per-repo cap on concurrent agent jobs is enforced (one until work claims exist) | `check_limits.py` (`effective_cap`, `admit`, `concurrency_group`); `tests/test_race.py` | Built; cap of 1 proven on a throwaway repo |
| P1.5 | The cap is raised only while the cross-agent conflict rate stays under target | `effective_cap`, `limits_store.conflict_status`; `tests/test_limits.py` `CapRaising` | Built; waits on P3.6 and real data |
| P1.5 | A monthly token budget alerts at 80% | `check_budget`, `config/limits.json` | Built; alert log line proven on a throwaway repo. The amount is a placeholder and the alert channel is unset |
| P1.5 | Hard stop when spent (from the task brief) | `check_budget` | Built and proven on a throwaway repo, before a run starts only; see [limits](#known-limits) |
| P1.5 | An agent can't open a new PR while 3 of its PRs wait for review (proposed) | `check_review_queue`, `review_queue.max_waiting_prs` | Built; proven on a throwaway repo |
| P1.6 | Gates and override process are announced to pilot teams | `docs/announcement-draft.md` | Draft; Process, not sent |
| P1.6 | Docs explain overrides and handoffs | `docs/pilot-team-guide.md`; `tests/test_integration_docs.py` | Built |
| P1.6 | Office hours are held before Phase 2 gates start blocking | `docs/office-hours-agenda.md` | Agenda only; Process |

## How the limits decide

**Order:** config, store, budget, concurrency, review queue. The first refusal ends the run, and each decision is logged as `LIMITS_DECISION`.

**Concurrency.** A run lists active agent workflow runs and takes its place by run ID. It proceeds if fewer than `cap` older runs are active, and otherwise polls for up to `wait_seconds`, then refuses. Older runs stay in the list until they finish, so a run's place only improves, and at most `cap` runs can be inside it. Nothing needs a lock or cleanup after a crash, and only read access is needed.

Each admitted run gets a GitHub concurrency group for its slot, so GitHub allows one running job per slot even if the list is briefly wrong. Slot numbers come from a run's place, so a run can wait behind another in its slot while a lower slot is free. That costs throughput only.

The plan says over-cap runs wait in a queue. This waits for a bounded time, because the pre-flight job has a 5-minute limit, then refuses.

**Conflict rate.** Uses `metrics/`'s own conflict calculation, per repo, over 14 days. Numerator: conflicted agent PRs that hit another agent PR, or where no overlap was found, since another agent can't be ruled out. Collisions with only human or other-bot PRs don't count. Same-agent collisions count because they're the risk parallel jobs add. The cap stays at 1 with fewer than 20 sampled PRs, or data over 48 hours old. The metrics README calls the rate a lower bound, so it can read better than reality.

**Budget.** Input plus output tokens from the `costs` table, for all agents and repos, in the current UTC month. It alerts at 80% or above on every run. It stops at 100%.

**Review queue.** Read live from GitHub, since the store is a day old. An agent's PR is one by its bot author or its `agent:` label. It's waiting until a human other than its author approves or requests changes on the current head. Drafts count, so an agent can't escape the limit by opening drafts. A run with `--target-pr` is exempt, because it opens no new PR and fix-ups shouldn't be blocked by the queue they would clear. Older active runs of the same agent count too, so racing runs can't overfill it.

**Fail closed.** These refuse with exit 2: a missing, corrupt or wrong-schema store, a fixture store, missing or stale cost data, spend recorded only in dollars, any GitHub API failure or truncated list, invalid config, an unlisted agent, or a run missing from its own list.

The store is opened read-only on purpose. `metrics`' `store.connect()` creates a missing database, which would read as zero spend.

## Placeholders and proposed values

| Item | Where | Status |
| --- | --- | --- |
| `budget.monthly_tokens` | `config/limits.json` | **Placeholder.** Refuses to run until set. Open question in the plan |
| `agents` | `config/limits.json` | Empty. Refuses every agent until filled in |
| `METRICS_STORE_REPO`, `METRICS_STORE_READ_TOKEN`, `LIMITS_ALERT_WEBHOOK` | Workflow patch | Set at install. A missing required secret doesn't stop the run at startup; the restore step refuses instead |
| `REPLACE_WITH_AGENT_NAME` | Caller in the patch | Per workflow |
| `max_waiting_prs: 3` | Config | Proposed in the ticket |
| `wait_seconds: 180`, `settle_seconds: 5`, `conflict_min_prs: 20`, `conflict_window_days: 14`, `conflict_data_max_age_hours: 48`, `cost_data_max_age_days: 3` | Config | Our numbers; tune from pilots |
| `conflict_rate_target: 0.15` | Config | From the plan's "under 15%" |
| `REPLACE_` values | `docs/` | Team, dates, channels |

No action SHA is new or invented: the patch reuses `kit/`'s pin of `actions/checkout`.

## What needs a real repo

**Read-only checks on `owxyz/agent-kit-sandbox`, 2026-11-09.** No writes were made. The check's own client listed the repo's 134 runs:

- A run of a workflow that calls the reusable pre-flight lists the caller's path (`.github/workflows/agent-run.yml`), with no `@ref` suffix. `agent-preflight.yml` never shows up as a run of its own.
- Of the sandbox's workflows, the default glob and exclusions count only `agent-run.yml`. Without the exclusions, `agent-provenance.yml` (42 runs) and `agent-kit-checks.yml` (18) would have taken slots. Dependabot runs list as `dynamic/...` and aren't counted.
- Run IDs followed creation order with no inversions. 74 neighbouring pairs shared a creation second, so ordering by timestamp wouldn't work. This is sequential history, not concurrent dispatches.
- The review-queue count read two open `agent:claude-code` PRs with no reviews as waiting, which is correct. It ignored the Dependabot PR.

**Live proofs on the throwaway private repo `owxyz/limits-proof-20261109`, 2026-11-10.** It held `kit/`'s pre-flight and agent workflow with the patch applied, a stand-in agent that holds its slot for a set time, and a store seeded by a workflow in the same repo. Settings were repo-level variables only.

| Scenario | Result |
| --- | --- |
| No store artifact | Restore step failed, the limits step was skipped and so was the agent job. The patched reusable workflow started with `actions: read` |
| Store at 90% of the budget | Allowed, with `LIMITS_ALERT` and a warning annotation. The run found itself in the list (`active: 1`), and the agent job held `agent-owner/repo`, kit's group |
| Three runs started at once, each holding 240 seconds | All three were created in the same second and each saw all three. The lowest run ID ran. The others were refused `concurrency` as numbers 2 and 3 after the 180-second wait |
| Two runs started at once, each holding 45 seconds | The second waited about 90 seconds, then took slot 0. The agent jobs didn't overlap |
| Three open `agent:claude` PRs | Refused `review_queue`. After one was closed, the next run was allowed |
| Store at 100% of the budget | First allowed, which was a bug: the artifact list isn't ordered by age, and `per_page=1` restored the older 90% store. After the fix to pick the newest unexpired artifact, refused `budget_spent` |

The same `per_page=1` pattern is in `metrics/templates/metrics-daily.yml`, which could restore an older store there too. It isn't changed here.

**Cross-repo proof, 2026-11-10.** The store sat in a separate throwaway private repo, `owxyz/limits-proof-store-20261110`. The agent repo, `owxyz/limits-proof-20261110`, read it with `METRICS_STORE_READ_TOKEN`, a fine-grained token limited to the store repo with Actions read only.

| Scenario | Result |
| --- | --- |
| Secret not set | GitHub ran the workflow anyway with an empty secret. The restore step failed and the agent job was skipped |
| Store at 90% | The store downloaded from the other repo. Allowed, with the alert |
| Store at 100%, seeded after the 90% store | The newest artifact was chosen. Refused `budget_spent` |

**Not yet tried on GitHub:**

- Concurrent dispatches at larger scale. Three in the same second all saw each other on the first read, but that's one sample.
- A dynamic concurrency group holding at a raised cap.
- The review-queue count against real human reviews and agent bot accounts. Labels were proven on the throwaway repo.
- A real alert webhook.

The conflict gate needs real collected data, and raising the cap needs P3.6.

## Known limits

- **The hard stop runs only before a run starts.** It can't stop a run in progress, and cost arrives by file import, so spend can overshoot. The plan's "stop the agent with a handoff" needs the runtime side.
- **The budget is only as current as the last import.** Usage from since then isn't counted.
- **Run ranking depends on GitHub's list.** A run slow to appear could let a newer run in. The two reads narrow this and the slot group bounds it.
- **Each agent needs its own workflow file** for same-agent counting, named `agent-<name>.yml` so the glob finds it.
- **A refused older run briefly holds its place** until it ends, which can delay a newer run.
- **Local agent use isn't counted** in the job cap, and a PR with no agent label from a non-bot account isn't counted in the queue.
- **The conflict calculation imports a private function** from `metrics/`, `report._conflicts`, because the public report isn't per repo. The tests fail if it changes shape.
- **`agent-name` is set by the calling workflow.** It's as trustworthy as owner review of workflow files (P2.1).

## Run the tests

Keep the virtual environment outside the project. PyYAML is needed only for the `kit/` linter run in the integration test.

```bash
python3 -m venv "$TMPDIR/limits-venv" && "$TMPDIR/limits-venv/bin/pip" install -r kit/requirements.txt
```

```bash
cd limits/tests && PYTHONDONTWRITEBYTECODE=1 "$TMPDIR/limits-venv/bin/python" -m unittest test_limits test_race test_fail_closed test_integration_docs
```
