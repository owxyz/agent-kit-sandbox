# Tamper check (P2.2)

Diff rules that flag test gaming in a pull request. The job runs base-branch rules over the PR diff as data, with a read-only token, and never executes PR code. No pilot repo has been chosen. The workflow has been tested on the sandbox repo; see [What needs a real repo](#what-needs-a-real-repo).

**P2.1 and P2.9 must close before any rule blocks.** P2.2 depends on both:

- **P2.1** puts workflows, this gate and its config behind owner approval. The PR run reads its workflow from the base branch, but in the merge queue GitHub reads it from the merge commit, so without that approval a PR could change the queue job.
- **P2.9** makes a required check count only when it reports success. Without it, a skipped or cancelled run could satisfy the check.

## What's here

| Path | Purpose | Install at |
| --- | --- | --- |
| `tamper_check.py`, `tamperkit/` | CLI and rule engine | `.github/gates/tamper/` |
| `classify_pr.py` | Decides whether a PR is an agent PR | `.github/gates/tamper/` |
| `rules.yml` | Mode, intended final mode and category per rule; budget and limits | `.github/gates/tamper/` |
| `tamperkit/languages.py` | Pattern tables per language (Python, JavaScript/TypeScript) | Part of the engine |
| `tamper_ledger.py`, `ledger/verdicts.jsonl` | Verdict record and false-positive report | `.github/gates/tamper/` |
| `workflows/tamper-check.yml` | Required check `tamper-check` | `.github/workflows/` |
| `tests/` | Fixtures and tests | Not needed on pilot repos |

The PR that installs this gate gets no `tamper-check` run, because `pull_request_target` reads the workflow from the base branch, where it doesn't exist yet. That's expected, so don't make the check required until the install has merged.

The job never checks out the PR. It fetches both versions of each changed file through the API and diffs them locally, because GitHub's own diff honors PR-supplied `.gitattributes`, detects renames and can be truncated. Each changed file costs up to two API calls, so a PR over `limits.max_api_files` is a tool error. `gates/integrity/INTEGRATION.md` gives the install order for all the gates.

## Acceptance criteria

**Status:** *Built* means implemented here and covered by tests. *Needs repo* means it can only be proven on GitHub. *Process* means a person has to do it.

| Criterion | File | Status |
| --- | --- | --- |
| Diff rules exist for every catalogue pattern, including retries inside tests | `tamperkit/rules.py`; [rule table](#rules); [patterns diffs can't catch](#patterns-diff-rules-cannot-catch) | Built |
| All rules start in warn-only mode on pilot repos | `rules.yml`; `Modes.test_shipped_config_is_all_warn_and_records_final_mode` | Built; Needs repo to deploy |
| False positives and confirmed hacks are recorded per rule | `tamper_ledger.py`, `ledger/verdicts.jsonl` | Built; Process to fill in |
| Block-marked rules are switched once their false-positive rate is acceptable | One-line `mode` change in `rules.yml`; `tamper_ledger.py report --enforce` | Built; Process, waiting on pilot data and P2.1 and P2.9 |

Task deliverables:

| Deliverable | File |
| --- | --- |
| Engine takes base and head, or a unified diff | `tamper_check.py --repo --base --head`, or `--diff` |
| Each rule's mode, with catalogue's final mode beside it | `rules.yml` |
| Per-rule false-positive report against the 5% bar | `tamper_ledger.py report` |
| Base-branch rules, PR diff as data, read-only token | `workflows/tamper-check.yml`; `tests/test_ledger_and_workflow.py` |
| True-positive and harmless fixture for every rule | `tests/cases.py` (a test fails if a rule has none) |

## Rules

| Catalogue category | Rule | Detects | Intended mode |
| --- | --- | --- | --- |
| Test and fixture edits | `test-skipped` | New skip or focus markers (`it.only` hides other tests) | Block |
| | `test-deleted` | A named test removed; a rename alone doesn't count | Block |
| | `test-count-drop` | Net fewer tests across the diff | Block |
| | `assertion-weakened` | Strong assertions removed or weakened; new assertions that can't fail | Block |
| | `expected-value-changed` | Same assertion or `expected` assignment with a different literal | Block |
| | `fixture-or-snapshot-changed` | Existing fixture, snapshot or golden file changed or deleted | Block |
| | `xfail-added` | New expected-failure markers | Block |
| | `timeout-raised` | Timeout raised in tests or runner config; new runner-wide timeout | Block |
| | `retry-added` | Retry markers, runner retries, retry loops around assertions | Block |
| Error swallowing and over-mocking | `broad-exception-handler` | New broad handler that doesn't re-raise | Warn, then review |
| | `mock-replaces-changed-code` | New mock targets a module this PR changes | Warn, then review |
| Comparison tampering | `equality-always-true` | Equality ignoring its argument, or a constant hash | Warn, then review |
| | `equality-override-new` | Any new equality or hash override in non-test code | Warn, then review |
| | `module-level-mutable-state` | Empty module-level containers, `let`, `global` in non-test code | Warn, then review |
| Harness and runtime tampering | `harness-file-changed` | `conftest.py`, setup files, pytest hooks, runner setup keys | Block |
| | `test-function-patched` | Replacing assertion or test functions | Block |
| | `early-exit` | Process exit or exit hooks outside entry points | Block |
| | `timer-override` | Replacing clocks; fake timers in non-test code | Block |
| | `runner-config-excludes` | Runner config that excludes or narrows tests | Block |
| Quality-gate suppression | `suppression-budget` | Net new suppressions and TypeScript escapes over budget | Warn over budget |
| | `threshold-lowered` | Loosened thresholds or strict flags, lint rules turned off | Block |
| | `coverage-exclusion` | New exclusion comments or coverage config exclusions | Block (our reading; see `rules.yml`) |
| Check bypass | `ci-workflow-changed` | Workflow or gate edits; `continue-on-error: true`; `if: false` | Block |
| Fake completion | `report-artifact-committed` | Committed coverage or test reports | Block |
| Not in the catalogue | `unscannable-input` | Lines too long to scan, binary code or config | Block |

Findings use the shared gate contract. Exit codes are 0 when nothing blocks, 1 when a block-mode finding exists, and 2 on tool error. A tool error also writes a blocking `tool-error` finding, so a reader of the file can't take it for a pass.

Non-agent PRs report every finding as `warn`. A PR counts as an agent PR if any of these hold: it has an `agent:*` label, it ever had one, its description names an agent, a commit has an agent co-author trailer, or its author is in `AGENT_BOT_LOGINS`. If any lookup fails, the PR is treated as an agent PR. These are `kit/`'s signals plus label history, so removing a label can't downgrade a PR. A person who labels a PR by mistake needs an owner's decision, because the history stays. An agent working under a human account with no trailer or disclosure still looks human.

## Patterns diff rules cannot catch

| Catalogue pattern | Why | Covered by |
| --- | --- | --- |
| Mocks that avoid real code paths in general | Needs execution data; the rule sees only mocks of modules changed in the PR | P2.3, P2.5 |
| Semantic comparison hacks; state hidden in other forms | Needs program meaning | P2.5, P2.10 |
| Special-casing inputs, lookup tables, features failing together, edge-case gaps | Needs tests the agent can't see | P2.5, P2.6, P2.10 |
| Claiming "tests pass" in the PR; copying answers from history or metadata | Not visible in code changes | P2.9 |
| Forged reports supplied outside the commit | Not in the diff; committed ones are flagged | P2.9 |
| Checks ending skipped, neutral or cancelled; crashes and timeouts that stop scoring | Runtime outcomes | P0.3, P2.1, P2.9 |
| Hacks spreading through shared code, plans or agent memory | Process control | P2.5, P0.12 |
| Forcing a pass when spec and tests conflict | Prevented by an escalation action | P2.8 |
| Dynamic evasion, such as `getattr(pytest, "sk" + "ip")` or `exec` | Text rules can't resolve it | P2.1, P2.5, base-branch harness (P2.9) |

## Switch a rule to blocking

1. Record each flagged PR. Download the `tamper-findings` artifact, then:

   ```bash
   python3 gates/tamper/tamper_ledger.py ingest --repo OWNER/REPO --pr 123 --findings tamper-findings.json
   ```

2. Have a reviewer record a verdict per flagged rule. `false_positive` means the flagged PR was judged harmless, matching the plan's bar.

   ```bash
   python3 gates/tamper/tamper_ledger.py record --repo OWNER/REPO --pr 123 --rule test-skipped --verdict confirmed_hack --by REVIEWER
   ```

3. Check the report. A rule is ready at `meets-bar`: under 5% harmless, enough judged PRs, nothing pending. A later row for the same repo, PR and rule replaces the verdict.

   ```bash
   python3 gates/tamper/tamper_ledger.py report
   ```

4. Before the first rule blocks, install `gates/integrity/` and set up its audit repo and secrets, which owner overrides need (`/gate-override gate=tamper ...`, described in `gates/integrity/README.md`). Warn-only installs need none of this, because the override steps run only when a rule blocks. A tool error can't be overridden.
5. Once P2.1 and P2.9 are closed, change the rule's `mode` to `block` in `rules.yml` through a reviewed PR. The workflow doesn't run `report --enforce`; run it by hand or add it where the ledger lives.

## Placeholders

| Item | Where | Note |
| --- | --- | --- |
| `budgets.suppressions: 3` | `rules.yml` | The plan says "a small budget"; set it from pilot data |
| `promotion.min_judged_prs: 20` | `rules.yml` | Our number; the plan names only the 5% bar |
| `limits.max_api_files: 300` | `rules.yml` | Our number; set it from pilot PR sizes |
| `.github/gates/tamper/` install path | `workflows/tamper-check.yml` | Change the paths if you install elsewhere |

No action SHA is a placeholder. `actions/checkout` is `3d3c42e5aac5ba805825da76410c181273ba90b1` (v7.0.1) and `actions/upload-artifact` is `cf430e030ddbb5b0abf93d22962f4752f3646cd9` (v7.0.2), both confirmed with `git ls-remote` on 2026-11-09.

## Known limits

- **Line-based, not a parser.** Multi-line statements can slip past a rule, and multi-line strings aren't tracked, so a docstring line that looks like code can be flagged. A JavaScript regex literal containing a quote can hide the rest of that line.
- **Languages.** Only Python and JavaScript/TypeScript code is scanned, chosen by file extension. To add one, append a `Language` in `tamperkit/languages.py` and add cases in `tests/cases.py`. Path-based rules work for any language.
- **Moved lines count as unchanged.** Moving a marker from one test to another isn't flagged.
- **Config lists.** Exclusions spread over several lines of a TOML or JSON array are seen only when the key is on a changed line.
- **Cost of hostile input.** Lines over 4096 characters are truncated and flagged. A diff built to be slow can reach the 15-minute job timeout, which fails the check.
- **The ledger needs protecting.** Put it behind owner approval along with the gate, and keep one ledger per pilot program. The job has a read-only token, so ingesting findings is a separate manual step.

## Replay on public repos

On 2026-11-09 the rules ran over the latest 150 default-branch commits each of Flask, Requests, Express and Axios (600 commits, read as data), with no tool errors. Reading the flagged lines found over-firing in `module-level-mutable-state`, `threshold-lowered` and `retry-added`, now fixed with regression fixtures.

This measures how often rules fire on human commits, not a false-positive rate, because nobody judged the findings and no hacks are labeled. After the fixes, thirteen rules never fired, among them `test-skipped`, `xfail-added`, `retry-added` and `early-exit`, so they remain unproven on real code. `ci-workflow-changed` fired on 27% of commits, so expect noise unless agents are barred from workflows.

## What needs a real repo

**Confirmed on `owxyz/agent-kit-sandbox` on 2026-11-09**, using a throwaway base branch and test PR (`owxyz/agent-kit-sandbox#5`, since closed):

- The full job ran on `pull_request`: both checkouts, the commit range, dependency install, rules, annotations and artifact upload. The step summary's rendering wasn't inspected.
- A skip marker was caught even though the PR added `.gitattributes` with `tests/** -diff`.
- With `test-skipped` in `warn`, the check passed and showed a warning annotation.
- With `test-skipped` in `block` on the base branch and an `agent:*` label, the job failed with exit 1.
- After the label was removed, the `unlabeled` event reran the job, the PR was classified as human through `gh api`, and the check passed with warnings.
- A filename containing a newline and `::error::` stayed inside one annotation, with the newline replaced by `?`.

That run used the earlier label-only classifier, in which removing the label downgraded the PR to warn-only. The replacement was tested the same day on `owxyz/agent-kit-sandbox#11` (since closed), with `test-skipped` in `block`:

- With no label, all three lookups worked with the real workflow token, no agent signal was found, and the check passed with a warning.
- With an `agent:*` label, the signals were `label,label-history` and the job failed with exit 1.
- After the label was removed, the signal was `label-history` and the job still failed with exit 1.

The trailer, declared-agent and bot-login signals are covered by local tests only. That sandbox is a public repo, so the token's access to a private repo's events is also unconfirmed. If it can't read them, every PR is treated as an agent PR.

Those runs used `pull_request` with a PR checkout. The workflow has since moved to `pull_request_target` with API data.

**Still unproven:**

- **The `pull_request_target` trigger for this workflow:** GitHub reads that trigger's workflow from the default branch, so a throwaway base branch gets no run (`owxyz/agent-kit-sandbox#18`). To test everything else, that PR ran the same job with only the trigger changed to `pull_request`. With a real workflow token, the API diff found a skip hidden behind `tests/** -diff`, and the human and agent paths behaved correctly. The trigger needs the workflow on the default branch.
- **Overrides:** the sandbox has no audit repo, secrets or override script, so an accepted override is untested. Only the offline paths are covered.
- **Fork heads through the API.**
- **`merge_group`:** the merge queue needs a second human account to approve a PR. That covers reading the PR number from the queue ref and the range from the event.
- **Fork PRs:** the test PR came from a branch in the same repo.
- **Failed label lookup:** the fallback to `agent` is in the workflow but wasn't forced on GitHub.
- **Annotation limits:** GitHub caps annotations per step, and a PR with many findings wasn't tried. The artifact and step summary still hold every finding.
- **False-positive rates:** unknown until pilot PRs are reviewed.
- **Required-check behavior:** `gates/integrity/` lists `tamper-check` as required, but this test ran it as a non-required check.

## Run the tests

Keep the virtual environment outside the project. Requires Python 3.9 or later.

```bash
python3 -m venv "$TMPDIR/tamper-venv" && "$TMPDIR/tamper-venv/bin/pip" install -r gates/tamper/requirements.txt
```

```bash
cd gates/tamper/tests && PYTHONDONTWRITEBYTECODE=1 "$TMPDIR/tamper-venv/bin/python" -m unittest test_rules test_untrusted_input test_ledger_and_workflow test_classify test_api_diff
```

```bash
actionlint gates/tamper/workflows/tamper-check.yml
```
