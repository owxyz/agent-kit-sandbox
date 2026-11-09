<!--
Copy to .github/PULL_REQUEST_TEMPLATE/agent-change.md.
Use for any change to an agent's level, model, prompt, tools or secrets.
Never paste a secret value into this PR.
-->

## What is changing

- Agent:
- Change: level / model / prompt / tools / secret / retirement

## Raising an autonomy level

- Promotion metric from the register:
- Target:
- Measured value and link to the data:

## Model, prompt or tool change

Required until the eval gate (P4.8) exists.

- Recent cases compared (link or list):
- Old version result:
- New version result:
- Change in how often the agent games tests:

## Checks

- [ ] `python3 inventory/validate.py register` passes, with any remaining `TBD` values explained
- [ ] A code owner has approved
- [ ] For a new key: added the new key, deployed it, then deleted the old one, and updated the dates in the register
- [ ] For a retired agent: uninstalled its app, revoked its keys and removed its register entries
