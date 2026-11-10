# Working with the agent gates: pilot team guide

**Status: draft.** No pilot team or pilot repo has been chosen, and none of this is installed on a real project. Parts were tested on the sandbox `owxyz/agent-kit-sandbox` on 2026-11-09. Rows marked **Not proven** have only passed local tests or are not fully set up on GitHub.

This guide covers what happens when an agent runs in your repo, what the checks on a PR mean, how to override one, and what happens when an agent gets stuck.

## The short version

- A person starts each agent run by hand, for now. Agents can't start themselves.
- Every agent PR needs a human code owner's approval. An agent can't approve its own work.
- Most checks read rules from your default branch, so a PR can't quietly change the rules applied to it.
- The tamper check only warns today. Other checks already block.
- A code owner can override two gates, with a written reason that gets logged. The other checks have no override.
- **Automated handoffs don't exist yet.** If an agent fails, a person picks up the work. See [Handoffs](#handoffs).

## Before an agent starts

Pre-flight runs first in every agent workflow. The first rule that fails ends the run, and each decision is logged with the prefix `PREFLIGHT_DECISION`.

| Rule | Refuses when | Proven on GitHub |
| --- | --- | --- |
| Kill switch | `AGENT_KILL_SWITCH` isn't exactly `off` | Yes |
| Write access | The person starting it lacks write access | Allowed path yes; a real refusal from a non-writer's comment is **Not proven** |
| Bot trigger | A bot set the label or assignment | **Not proven** |
| Fork PR | The target PR comes from a fork | **Not proven** |
| Containment | The repo isn't on the pilot list, the trigger isn't manual, or a manual run didn't start from the default branch | Off-list repo and feature-branch dispatch yes; manual-only on another event is **Not proven** |

**Limits (P1.5) are built but not yet connected.** `limits/INTEGRATION.md` is the step that adds them to pre-flight. **Not proven** on GitHub. Once connected:

| Refusal in the log | Meaning | What to do |
| --- | --- | --- |
| `concurrency` | The repo's agent slots stayed full for the wait period (180 seconds as shipped) | Start the run again when the other agent finishes |
| `budget_spent` | The month's token budget is used up | Talk to the budget owner. Runs resume next UTC month, or sooner if the budget is raised |
| `review_queue` | This agent has 3 PRs waiting for human review in this repo (proposed limit) | Review or close one. Work on an existing PR isn't blocked |
| Rule starting `budget_`, `store_`, `config`, `github_api`, `run_not_listed` | The check couldn't get a reliable answer, so it refused | Tell the platform team. This isn't something to fix in your PR |

At 80% of the budget, runs continue and an alert goes out.

## Checks on a pull request

"Blocks" means the required check fails and the PR can't merge. A warning shows on the PR but doesn't stop it.

A PR counts as an agent PR if it has an `agent:*` label, names an agent in its description, has an agent co-author trailer, or was opened by a listed agent account. `tamper-check` also counts a label the PR used to have, and treats a failed lookup as an agent PR. `provenance` and `test-quality` look at the PR's current state only, so removing the label can change their answer if nothing else marks the PR. An agent working under a person's account with no trailer or disclosure still looks human.

| Check | What it looks at | Agent PR | Human PR | Override | Proven on GitHub |
| --- | --- | --- | --- | --- | --- |
| `provenance` | The PR's disclosure fields | **Blocks** if the agent label, model, prompt version or session log is missing | **Blocks** if "Agent used" is empty (write `none`) or a commit has an undisclosed agent trailer | None; fill in the fields | Yes |
| `workflow-lint` | Agent workflow safety | **Blocks** | **Blocks** | None; fix the workflow | Yes |
| `tamper-check` | Test gaming in the diff | **Warns**: all 25 rules ship in warn mode | Warns | `/gate-override gate=tamper`, once a rule blocks | Warn and block yes; an accepted override is **Not proven** |
| `test-quality`: changed-code coverage, fail-before/pass-after | Coverage of changed branches and error handlers; new tests against the old code | **Blocks** | Warns | None; see [owner approvals](#owner-approvals-in-test-quality) | Earlier version only. The current container boundary is **Not proven** |
| `test-quality`: repeat runs, blocking suite | New or changed tests run 10 times; the suite's non-quarantined tests | **Blocks** | **Blocks** | None | Same |
| `heldout-tests` | Private tests on critical modules | **Blocks** | **Blocks** | None | **Not proven**; needs its private repo and two GitHub Apps |
| `check-integrity` | Workflow rules (`INT` and `CACHE`) | **Blocks** on block-mode rules; `INT005`, `INT006`, `CACHE003` and `CACHE004` warn | Same | `/gate-override gate=integrity` | Parts of the rules' GitHub assumptions. The shipped workflow is **Not proven** |
| `required-checks-verified` | That each required check really reported success from the expected app | **Blocks** | **Blocks** | None; fix the underlying check | Verifier logic on test PRs; the full set is **Not proven** |

Merge queue: the whole queue path is **Not proven**, because it needs a second human account to approve a PR.

### Tamper rules will start blocking one at a time

A rule moves from warn to block only after reviewers have judged its flagged PRs, it shows under 5% judged harmless, and an owner changes its mode in a reviewed PR. So your verdicts on warnings during the pilot decide what blocks later.

**Expect noise from `ci-workflow-changed`.** It fired on 27% of commits in a replay on public projects.

## Overrides

Overrides exist for gates that are wrong about a specific PR. They aren't a way to get past a real finding.

**Available for:** `tamper` and `integrity`. Other gates could adopt this later, but aren't wired to it today.

**How:**

1. A code owner comments on the PR, as one comment:

   ```text
   /gate-override gate=tamper sha=abc1234 reason: The fixture rename is intended; the data did not change.
   ```

2. Re-run the failed gate job. A comment doesn't re-run it.
3. Re-run `required-checks-verified`.

**It's accepted only if all of these hold:**

- It names this gate and the PR's current commit, with at least the first 7 characters of the SHA. **Any new push voids it.**
- The reason has at least 20 characters and 3 words.
- The commenter owns every file with a blocking finding under the default branch's CODEOWNERS, and has write access. PR-wide findings use the catch-all owner.
- The commenter is a person and didn't author the PR.
- The comment has never been edited. To fix a typo, post a new comment.

**What can't be overridden:** a tool error (exit 2). The gate failed to reach a verdict, so it needs fixing or re-running.

**What's recorded:** each block, accepted override and rejected attempt goes in an append-only log in a private audit repo, before the override takes effect. If logging fails, nothing passes. A weekly report gives the override rate per gate and opens a review issue. A rising rate means the gate needs tuning.

**In the merge queue**, an override counts only if the log recorded that rule and file for the PR's current commit. A batch of queued PRs can block on a finding from an earlier PR in the group.

**Not proven:** real team lookups, the audit repo, and a full accepted override on GitHub. Until `CODEOWNERS` has real teams, nobody can override.

### Owner approvals in test-quality

`test-quality` has no override command. A listed owner (the `TEST_QUALITY_OWNERS` variable) can approve a few specific things by approving the PR's current commit: new coverage exclusion comments, a new `conftest.py` or similar test-tool config, and changes the measurement scan flags. **Not proven** against real reviews, because it needs a second account.

## Handoffs

**The automated handoff (P3.3, Phase 3) isn't part of the gates today.** Neither `gates/` nor `kit/` posts a handoff comment. Fix-loop and escalation work is being built separately in `runtime/` and isn't connected to these gates or covered by this guide.

For this pilot:

| Situation | What happens now | Who acts |
| --- | --- | --- |
| A gate fails on an agent PR | The PR stays blocked, with the finding on the check. The agent doesn't get an automatic retry | The person who started the run, or the PR's reviewer |
| You take over an agent's PR | Push your fix to its branch and carry on. **Keep the `agent:*` label and disclosure**: the agent's work is still in the PR, so agent rules still apply, and `tamper-check` keeps treating it as an agent PR even if the label goes | You; a code owner reviews it |
| An agent run fails or times out | Read the workflow log and the session log linked in the PR | The person who started the run |
| Budget runs out mid-run | The check only runs before an agent starts, so a run in progress isn't stopped by it. The plan's handoff on a spent budget isn't built | Budget owner |
| Agent behaves dangerously | Follow `kit/runbooks/kill-switch.md`, then `kit/runbooks/incident-response.md` | Anyone with access to the org variable |

The planned handoff is a PR comment with the failure class, a log excerpt, whether `main` also fails, each attempt and the best-guess cause. Some will include a suggested patch to review, never for protected paths like tests and workflows.

## Reviewing agent PRs

Read the warnings as well as the failures. A passing PR can still have gamed its tests, and known gaps exist: code can behave differently under test, and a test can misreport its own result in the same process. Your review covers what these checks can't.

Every push after an approval dismisses that approval, and the latest push needs approving. **Not proven** beyond the ruleset being accepted.

## Getting help

- Office hours: `REPLACE_WITH_OFFICE_HOURS_TIME`
- Channel: `REPLACE_WITH_SUPPORT_CHANNEL`
- Platform contact: `REPLACE_WITH_PLATFORM_CONTACT`
