# Flag for human (P2.8)

`flag-for-human` is installed in the agent image. It posts to the gateway, which logs the flag outside the sandbox.

After the task, the runner adds the agent's name and appends the flags to the ledger. A flagged task exits 3, whatever the agent's own exit code was.

The rate is the share of an agent's tasks with at least one flag:

```bash
python3 runtime/escalation/flag_ledger.py report --ledger LEDGER.jsonl
```

The ticket sets no target rate. Read it both ways: near zero may mean an agent is forcing passes rather than flagging, and a high rate may mean it gives up too easily or the specs are poor.

`flag_ledger.py comment` renders the PR comment, with agent-written text inside a code fence so it can't mention people or inject markup.

## Durable ledger (R1.10)

The runner's ledger lives in its temp folder and is gone when the job ends. The workflow's last step appends each task's record to `flag-ledger.jsonl` in the gate audit repo, `owxyz/gate-audit` (decision D6):

```bash
python3 runtime/escalation/ledger_store.py append --audit-repo owxyz/gate-audit --ledger "$RUNNER_TEMP/flag-ledger.jsonl" --allow-missing
python3 runtime/escalation/ledger_store.py fetch --audit-repo owxyz/gate-audit --output ledger.jsonl
python3 runtime/escalation/flag_ledger.py report --ledger ledger.jsonl
```

- **Agents can't edit it.** The agent App isn't installed on the audit repo, and only the persist step holds `AUDIT_REPO_TOKEN`, a fine-grained token for that repo alone. The repo's `audit-log-append-only` ruleset blocks deletion and force pushes.
- **Edits show.** It uses the gate audit log's hash chain (`gates/integrity/scripts/audit_log.py`). A changed, removed or reordered line fails `verify` and stops later appends. To catch lines cut off the end, keep a head from an earlier `verify` and pass it as `--expect-head`.
- **Created once.** `init` makes the file, and `append` never does, so a deleted ledger stops appends. `flag-ledger.jsonl` was created on 2026-11-14.
- **Reruns are safe.** A record already stored, by task, agent and time, isn't added again.

**Proven on 2026-11-14** with sandbox run 43688539690, from a proof branch that's now deleted:
- Job `write` appended a task record to `proofs/flag-ledger-r110.jsonl` on runner 1000003082.
- Job `read` ran on runner 1000003083 with no local ledger. It used the read-only `AUDIT_REPO_READ_TOKEN` to verify the chain against the written head and fetch the record.
- Rerunning only `read`, on runner 1000003084, verified the same head.
- A token minted for the agent App got 404 for the audit repo, the ledger file, and a write to it.
