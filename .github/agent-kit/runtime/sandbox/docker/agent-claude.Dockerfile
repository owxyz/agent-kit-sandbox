# Agent image with Claude Code: the base agent image plus the CLI at an exact version.
# Build with the runtime/ folder as context, after agent.Dockerfile:
#   docker build -t runtime-agent:dev -f sandbox/docker/agent.Dockerfile .
#   docker build -t runtime-agent-claude:VERSION -f sandbox/docker/agent-claude.Dockerfile \
#     --build-arg CLAUDE_CODE_VERSION=VERSION .
# Then publish it and run it by digest (runner.py refuses an unpinned image).
#
# Install scripts stay off for every package. Claude Code's npm package ships a
# placeholder binary, and only its own install.cjs links the platform's native
# one, so that single installer runs explicitly. Without it the image builds but
# `claude` fails with "exec format error" (red-team finding #16). The version
# check below makes that a build failure instead.
ARG BASE_IMAGE=runtime-agent:dev
FROM ${BASE_IMAGE}
ARG CLAUDE_CODE_VERSION=2.1.323
USER root
RUN test -n "$CLAUDE_CODE_VERSION" \
 && npm install -g --ignore-scripts "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
 && cd /usr/local/lib/node_modules/@anthropic-ai/claude-code && node install.cjs \
 && npm cache clean --force \
 && claude --version | grep -q "^${CLAUDE_CODE_VERSION} "
USER 1000:1000
ENV DISABLE_TELEMETRY=1 DISABLE_ERROR_REPORTING=1 DISABLE_AUTOUPDATER=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
