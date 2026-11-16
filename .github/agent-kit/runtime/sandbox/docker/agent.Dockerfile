# Base image for agent tasks: Python, Node, git, the test tools and the flag-for-human
# command. Add your agent CLI at an exact version in a derived image.
# Build with the runtime/ folder as context.
FROM node:24-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9 AS node
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN apt-get update \
 && apt-get install -y --no-install-recommends git make \
 && rm -rf /var/lib/apt/lists/*
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx
# Test tools, because the sandbox blocks public registries (red-team #12). Exact
# versions and hashes from agent-tools.txt; regenerate it with lock_agent_tools.py.
COPY sandbox/docker/agent-tools.txt /tmp/agent-tools.txt
RUN pip install --no-cache-dir --disable-pip-version-check --root-user-action=ignore \
      --require-hashes --no-deps --only-binary=:all: -r /tmp/agent-tools.txt \
 && rm /tmp/agent-tools.txt \
 && pip check \
 && ruff --version && mypy --version && python -m pytest --version
COPY escalation/flag_for_human.py /usr/local/bin/flag-for-human
RUN chmod 0755 /usr/local/bin/flag-for-human \
 && useradd --uid 1000 --create-home agent \
 && mkdir /workspace && chown agent:agent /workspace
USER 1000:1000
WORKDIR /workspace
