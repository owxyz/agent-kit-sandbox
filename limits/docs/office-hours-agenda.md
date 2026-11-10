# Office hours agenda: agent gates

**DRAFT. No session has been scheduled or held.** P1.6 requires office hours before Phase 2 gates start blocking, so hold them before any tamper rule moves to `block`. Note that `test-quality`, `check-integrity` and `required-checks-verified` block from install, so hold a session before those are made required too.

- **When:** `REPLACE_WITH_OFFICE_HOURS_TIMES`
- **Length:** 45 minutes
- **Host:** `REPLACE_WITH_HOST`, plus a code owner from each pilot team
- **Before:** share `limits/docs/pilot-team-guide.md`

| Minutes | Topic | Notes |
| --- | --- | --- |
| 0 to 5 | Why these gates exist | Agents can game tests, and review is the bottleneck |
| 5 to 15 | Walk through a PR | Show each check, and what's warning versus blocking today. Use a real sandbox PR, and say it's a sandbox |
| 15 to 25 | Overrides, live | Write a valid `/gate-override`. Then show what voids one: a new push, an edited comment, a short reason, the PR's author. Say which gates have none |
| 25 to 30 | When an agent gets stuck | No automated handoff yet. Show how to take over a PR and why the `agent:*` label stays on. Show the kill switch |
| 30 to 35 | Limits | One agent per repo, the review queue of 3 (proposed), the 80% alert and hard stop. Say these aren't connected yet |
| 35 to 45 | Your questions and your repos | Note anything that would break your workflow |

## Questions to ask the teams

- Who are the code owners for tests, workflows and agent config?
- Which checks would be slowest on your repo? What's your normal test time?
- Who should get the 80% budget alert?
- Is 3 waiting PRs per agent right for how fast you review?
- Which modules are critical enough for held-out tests?

## What to say isn't proven

Be direct about these: the merge queue path, an accepted override end to end, held-out tests, agent App identity, the limits check on GitHub, and any run on a real project.

## Record after each session

| Date | Team | Attended | Blocking concerns | Follow-up owner |
| --- | --- | --- | --- | --- |
| | | | | |

The P1.6 criterion that office hours were held is met only when this table has an entry from every pilot team.
