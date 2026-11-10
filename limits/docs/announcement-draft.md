# Announcement draft: agent gates for pilot teams

**DRAFT. NOT SENT.** Fill in each `REPLACE_` value and confirm the status lines still hold before anyone sends this.

**To:** `REPLACE_WITH_PILOT_TEAM_LIST`
**From:** `REPLACE_WITH_SENDER`
**Subject:** New checks on agent pull requests in `REPLACE_WITH_PILOT_REPOS`, starting `REPLACE_WITH_START_DATE`

Hi all,

Your team is part of the pilot for running coding agents through CI. From `REPLACE_WITH_START_DATE`, new checks will run on pull requests in `REPLACE_WITH_PILOT_REPOS`. Here's what changes for you.

**What you'll notice**

- Agent runs are started by hand, and each repo runs one agent at a time.
- Every agent PR needs approval from a human code owner.
- The PR template has new disclosure fields. On human PRs, write `none` under "Agent used", or the `provenance` check fails.
- Some checks also block human PRs, such as tests that fail when run repeatedly. Others only warn on human PRs. The guide lists each one.

**What's warning and what's blocking**

The tamper check starts in warn-only mode. Rules move to blocking one at a time, once reviewers have confirmed they're accurate, so please give a verdict when you're asked about a warning. Other checks, including `test-quality` on agent PRs, block once installed.

**If a check is wrong about your PR**

Code owners can override the tamper and integrity gates with a written reason in a PR comment. Each override is logged and reviewed weekly, and a new push cancels it. Other checks have no override.

**If an agent gets stuck**

There are no automated handoffs yet. A person picks up the work, using the run log and the PR's session log. The guide explains how.

**Still being proven**

Parts of this have only run on a test repo. The merge queue path, accepted overrides and held-out tests haven't been confirmed on GitHub yet, so expect some rough edges. Tell us when you hit one.

**Office hours**

Please come to one session before any gate starts blocking: `REPLACE_WITH_OFFICE_HOURS_TIMES`. Bring a PR you'd like to walk through.

Full guide: `REPLACE_WITH_GUIDE_LINK`
Questions: `REPLACE_WITH_SUPPORT_CHANNEL`

Thanks,
`REPLACE_WITH_SENDER`
