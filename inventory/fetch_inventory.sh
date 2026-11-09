#!/usr/bin/env bash
# Clone an org's repos and record its credential names, for an operator to run.
# GitHub is only read. Secret values are never returned by these APIs.
#
# Usage: fetch_inventory.sh ORG OUTPUT_DIR
# Then:  python3 inventory/scan_workflows.py OUTPUT_DIR/repos
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 ORG OUTPUT_DIR" >&2
  exit 2
fi
org=$1
out=$2
mkdir -p "$out/repos" "$out/credentials"
failures="$out/credentials/unavailable.txt"
: > "$failures"

# Save one API result; a call we lack access to is recorded, not fatal.
fetch() {
  local file=$1 endpoint=$2 filter=$3
  if ! gh api --paginate "$endpoint" --jq "$filter" > "$out/credentials/$file" 2>/dev/null; then
    echo "$endpoint" >> "$failures"
    rm -f "$out/credentials/$file"
  fi
}

gh repo list "$org" --limit 1000 --no-archived --json nameWithOwner \
  --jq '.[].nameWithOwner' > "$out/repos.txt"

fetch org-secrets.txt "/orgs/$org/actions/secrets" '.secrets[].name'
fetch org-workflow-permissions.json "/orgs/$org/actions/permissions/workflow" '.'
fetch org-app-installations.json "/orgs/$org/installations" \
  '.installations[] | {app_slug, permissions, repository_selection}'
fetch org-fine-grained-pats.json "/orgs/$org/personal-access-tokens" \
  '.[] | {id, owner: .owner.login, repository_selection, permissions, token_expires_at}'
fetch org-sso-credentials.json "/orgs/$org/credential-authorizations" \
  '.[] | {login, credential_type, scopes, credential_authorized_at}'

while read -r full; do
  repo=${full#*/}
  if [ ! -d "$out/repos/$repo" ]; then
    gh repo clone "$full" "$out/repos/$repo" -- --depth 1 --quiet || echo "clone $full" >> "$failures"
  fi
  fetch "$repo.secrets.txt" "/repos/$full/actions/secrets" '.secrets[].name'
  fetch "$repo.deploy-keys.json" "/repos/$full/keys" '.[] | {id, title, read_only, created_at}'
  if environments=$(gh api --paginate "/repos/$full/environments" --jq '.environments[].name' 2>/dev/null); then
    while read -r environment; do
      [ -n "$environment" ] || continue
      fetch "$repo.env-$environment.secrets.txt" \
        "/repos/$full/environments/$environment/secrets" '.secrets[].name'
    done <<< "$environments"
  else
    echo "/repos/$full/environments" >> "$failures"
  fi
done < "$out/repos.txt"

echo "Done. Calls that were unavailable are listed in $failures"
