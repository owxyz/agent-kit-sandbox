#!/usr/bin/env python3
"""Check PR provenance fields and flag undisclosed agent co-authors (P1.4).

Usage: check_provenance.py --event EVENT.json [--agent-logins a,b]
           [--commits-file commits.json] [--github-output FILE]

Commits come from the GitHub API unless --commits-file is given. Findings name
fields and short SHAs only, so PR text never reaches the log. Standard library.
"""
import argparse
import json
import os
import re
import sys
import urllib.request

FIELDS = ("Agent used", "Model", "Prompt version", "Session log", "Local agent")
UNFILLED = {"", "tbd", "todo", "?", "unknown"}
DEPENDENCY_BOTS = {"dependabot[bot]", "renovate[bot]"}
TRAILER = re.compile(r"^\s*co-authored-by:\s*(?P<name>[^<\n]*)<(?P<email>[^>\n]*)>", re.I | re.M)
AGENT_EMAIL = re.compile(
    r"@anthropic\.com$|@openai\.com$|cursoragent@cursor\.com$|@aider\.chat$"
    r"|\+?(copilot|claude|codex|devin-ai-integration|gemini-code-assist|cursor)(\[bot\])?"
    r"@users\.noreply\.github\.com$",
    re.I,
)
AGENT_NAME = re.compile(r"\[bot\]\s*$", re.I)
PER_PAGE = 100
MAX_PAGES = 3  # GitHub returns at most 250 commits for a pull request.


def parse_fields(body):
    text = re.sub(r"<!--.*?-->", "", body or "", flags=re.S)
    values = {}
    for field in FIELDS:
        match = re.search(
            r"^[ \t]*[-*]?[ \t]*\**[ \t]*%s[ \t]*\**[ \t]*:[ \t]*\**[ \t]*(.*?)[ \t]*$" % re.escape(field),
            text, re.I | re.M,
        )
        values[field] = match.group(1).strip() if match else ""
    return values


def filled(value):
    return value.strip().lower() not in UNFILLED


def agent_trailer_commits(commits):
    flagged = []
    for commit in commits:
        message = (commit.get("commit") or {}).get("message") or ""
        for match in TRAILER.finditer(message):
            name, email = match.group("name").strip(), match.group("email").strip()
            lowered = name.lower()
            if lowered in DEPENDENCY_BOTS or lowered.startswith("github-actions"):
                continue
            if AGENT_EMAIL.search(email) or AGENT_NAME.search(name):
                flagged.append(str(commit.get("sha", ""))[:7])
                break
    return flagged


def evaluate(pr, commits, agent_logins):
    """Return (findings, notices, is_agent_pr)."""
    author = ((pr.get("user") or {}).get("login") or "").lower()
    if author in DEPENDENCY_BOTS:
        return [], ["dependency bot PR; provenance fields not required"], False
    fields = parse_fields(pr.get("body"))
    labels = [str(l.get("name", "")) for l in pr.get("labels") or []]
    has_agent_label = any(l.lower().startswith("agent:") and len(l) > 6 for l in labels)
    agent_used = fields["Agent used"].lower()
    declared = filled(agent_used) and agent_used != "none"
    flagged = agent_trailer_commits(commits)
    is_agent = declared or has_agent_label or bool(flagged) or author in agent_logins

    findings, notices = [], []
    if not filled(agent_used):
        findings.append('"Agent used" is missing; write "none" if no agent was used')
    if flagged and not declared:
        findings.append("agent co-author trailer on undisclosed commit(s): " + ", ".join(flagged))
    elif flagged:
        notices.append("agent co-author trailer on commit(s): " + ", ".join(flagged))
    if is_agent:
        if not has_agent_label:
            findings.append("agent PR needs an agent:<name> label")
        for field in ("Model", "Prompt version"):
            if not filled(fields[field]):
                findings.append('agent PR is missing "%s"' % field)
        log_is_link = fields["Session log"].lower().startswith("https://")
        if fields["Local agent"].lower() == "yes":
            if not log_is_link:
                notices.append("local agent PR has no session log link")
        elif not log_is_link:
            findings.append('agent PR needs an https "Session log" link')
    return findings, notices, is_agent


def fetch_commits(repository, number):
    base = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    commits = []
    for page in range(1, MAX_PAGES + 1):
        url = "%s/repos/%s/pulls/%s/commits?per_page=%d&page=%d" % (
            base, repository, number, PER_PAGE, page)
        request = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + os.environ.get("GITHUB_TOKEN", ""),
        })
        with urllib.request.urlopen(request, timeout=30) as response:
            batch = json.load(response)
        commits.extend(batch)
        if len(batch) < PER_PAGE:
            break
    return commits


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", required=True)
    parser.add_argument("--agent-logins", default="")
    parser.add_argument("--commits-file")
    parser.add_argument("--github-output")
    args = parser.parse_args()
    logins = {p.strip().lower() for p in args.agent_logins.split(",") if p.strip()}
    try:
        with open(args.event, encoding="utf-8") as handle:
            event = json.load(handle)
        pr = event["pull_request"]
        if args.commits_file:
            with open(args.commits_file, encoding="utf-8") as handle:
                commits = json.load(handle)
        else:
            commits = fetch_commits(event["repository"]["full_name"], pr["number"])
    except Exception as error:
        print("::error title=Provenance::could not load PR data: %s" % type(error).__name__)
        return 1
    findings, notices, is_agent = evaluate(pr, commits, logins)
    for notice in notices:
        print("::notice title=Provenance::%s" % notice)
    for finding in findings:
        print("::error title=Provenance::%s" % finding)
    if args.github_output:
        with open(args.github_output, "a", encoding="utf-8") as output:
            output.write("agent_pr=%s\n" % str(is_agent).lower())
    print("agent_pr=%s findings=%d" % (str(is_agent).lower(), len(findings)))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
