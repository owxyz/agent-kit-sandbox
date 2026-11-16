# Minting the agent's GitHub token

`mint_installation_token.py` is tested against a local stand-in for the API, signing with a real RSA key. It has also minted and revoked a real token for the sandbox App `owxyz-coding-agent` (App ID 5709045, installed on `owxyz/agent-kit-sandbox` only) on 2026-11-11.

## Setup, once per agent

1. Create a GitHub App for the agent in the org, one App per agent (P0.2). Turn webhooks off.
2. Repository permissions: Contents read and write, Pull requests read and write, Metadata read, as P0.2 requires. Don't grant Administration, Workflows, Actions, Secrets or Variables. If an agent needs Issues, grant it on the App and pass `--permissions contents=write,pull_requests=write,issues=write`.
3. Install it only on the pilot repositories.
4. Generate a private key and store it in a secrets manager or an Actions secret available only to the job that launches the sandbox.

## Per task

```bash
python3 runtime/sandbox/mint_installation_token.py mint --app-id "$APP_ID" --private-key "$KEY_PEM" --repo OWNER/NAME --output "$RUNNER_TEMP/gh-token"
```

On a Mac, the key can stay in the Keychain instead of a file. Store it base64-encoded, with `security add-generic-password -a ACCOUNT -s SERVICE -w "$(base64 < key.pem)"`. Then pass `--private-key-keychain SERVICE`, plus `--keychain-account ACCOUNT` if it isn't `owxyz`, in place of `--private-key`. The key reaches `openssl` through a pipe, so it's never written to disk. owxyz's agent App key is the item `owxyz-coding-agent-app-key`, and `runtime.env` names it as `AGENT_APP_KEYCHAIN_SERVICE`.

The script:

1. Signs a JWT for the App, valid for under 10 minutes.
2. Looks up the installation for that repository.
3. Calls `POST /app/installations/{id}/access_tokens` with `repositories: [NAME]` and the permissions list.
4. Refuses the result unless it covers exactly that repository, has no permission that wasn't requested, and expires within about an hour.
5. Writes the token to a 0600 file and prints only the expiry.

Then pass it to the sandbox, and revoke it when the task ends:

```bash
python3 runtime/sandbox/runner.py --task-id T --agent NAME --image IMAGE@sha256:DIGEST --allowlist ALLOWLIST.json --repo OWNER/NAME --issue ISSUE --model-key-file KEY --github-token-file "$RUNNER_TEMP/gh-token" --ledger LEDGER.jsonl -- COMMAND
```

```bash
python3 runtime/sandbox/mint_installation_token.py revoke --token-file "$RUNNER_TEMP/gh-token"
```

## Where the token lives

Only in the gateway's memory. The runner sends it on the gateway's stdin, and the agent container never holds it. The agent's git and API calls go to the gateway, which adds the token and permits only this repository's paths. A task can't outlive the token by much, because the runner's default timeout is also one hour. GitHub rejects a push after expiry.

A task that needs longer has to restart with a new token. There's no refresh inside the gateway, by design.

## Commit identity

Commits the App pushes must use its bot account's user id, not the App id, or GitHub links them to no account:

```bash
git config user.name 'owxyz-coding-agent[bot]'
git config user.email '355238002+owxyz-coding-agent[bot]@users.noreply.github.com'
```

Look up the id with `gh api 'users/owxyz-coding-agent[bot]' --jq .id`. With the App id (5709045) instead, pilot PR 229's commits showed no author. The pilot's review ruleset sets `require_extra_approval_for_unattributed_changes`, so it held the PR for a second approval that a single maintainer can't give.
