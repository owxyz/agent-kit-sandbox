# Connecting the limits check to the agent pre-flight

The check runs as the last step of `kit/`'s pre-flight, after its other rules pass. It hasn't been applied to `kit/` or run on GitHub. `integration/agent-preflight.patch` holds the exact edit, and a test applies it to `kit/`'s current files so drift shows up as a failing test.

## Before you start

1. Finish `kit/README.md`'s install, and start the daily metrics collection from `metrics/README.md`.
2. Fill in `config/limits.json`: set `budget.monthly_tokens`, and add each agent under `agents`, with the same labels and bots as `metrics/config.json`.
3. Import usage into the store at least daily with `agentmetrics import-costs`. The file import isn't automated. The check refuses if the newest row is over 3 days old, or if there are no rows. For the very first run only, set `allow_empty_cost_history` to `true`, then set it back.

## Steps

1. Copy the code through a reviewed PR. `.github/agent-kit/` is already behind the check owners in `kit/templates/CODEOWNERS`:

   | From | To |
   | --- | --- |
   | `limits/scripts/`, `limits/config/` | `.github/agent-kit/limits/` |
   | `metrics/agentmetrics/` | `.github/agent-kit/metrics/agentmetrics/` |

2. Apply the patch to your workflows from the repo root:

   ```bash
   patch -p1 -d .github/workflows < limits/integration/agent-preflight.patch
   ```

   It changes `agent-preflight.yml` and the `agent-run.example.yml` pattern. Make the same caller change in every `agent-<name>.yml`, and set `agent-name` to that agent's name in the config.

3. Set these:

   | Kind | Name | Value |
   | --- | --- | --- |
   | Org variable | `METRICS_STORE_REPO` | `owner/name` of the private repo that runs `metrics-daily` |
   | Secret | `METRICS_STORE_READ_TOKEN` | Token with only Actions read on that repo |
   | Secret, optional | `LIMITS_ALERT_WEBHOOK` | HTTPS webhook for the 80% alert. Without it, the alert is only a log line and a warning annotation |

4. Run a manual dispatch and look for `LIMITS_DECISION` in the log.

## What the patch changes

- Adds `actions: read` to the pre-flight job and its caller, which listing workflow runs needs.
- Adds a required `agent-name` input and a required `metrics-store-token` secret.
- Adds three steps after `Evaluate pre-flight rules`: check out the two folders from the default branch, download the store, run the check.
- Points the `allowed` and `concurrency-group` outputs at the limits step. If an earlier step fails, `allowed` is empty and the agent job is skipped.

The checkout reuses `kit/`'s pin, `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` (v7.0.1). No new action is added.

## Raising the cap later

The agent job keeps using the pre-flight's `concurrency-group`. That's slot 0 at a cap of 1, the same name as `kit/`'s group. When the cap is above 1, later slots get `agent-owner/repo-slot-N`, so GitHub itself allows at most one running job per slot.

To raise it, after P3.6 ships: set `work_claims_enabled` to `true` and `raised_max_jobs` above 1 through a reviewed PR. The cap drops back to 1 by itself on any run where the rate reaches target, the data is stale, or there are too few PRs.
