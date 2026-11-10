"""Config loading and shared errors for the P1.5 limits check."""
import json
import re

PLACEHOLDER = "REPLACE_WITH_MONTHLY_TOKEN_BUDGET"
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
AGENT_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


class Refused(Exception):
    """A limit was reached. Exit 1."""

    def __init__(self, rule, message):
        super().__init__(message)
        self.rule, self.message = rule, message


class ToolError(Exception):
    """The check could not decide. Exit 2, and the agent does not run."""

    def __init__(self, rule, message):
        super().__init__(message)
        self.rule, self.message = rule, message


def _fail(message):
    raise ToolError("config", message)


def _keys(section, name, required):
    if not isinstance(section, dict):
        _fail("%s must be an object" % name)
    got = {k for k in section if not k.startswith("_")}
    if got != required:
        _fail("%s: missing %s, unknown %s" % (name, sorted(required - got) or "none", sorted(got - required) or "none"))


def _int(value, name, low, high=None):
    if isinstance(value, bool) or not isinstance(value, int) or value < low or (high is not None and value > high):
        _fail("%s must be a whole number from %s%s" % (name, low, " to %s" % high if high is not None else " up"))
    return value


def _number(value, name, low, high):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
        _fail("%s must be a number from %s to %s" % (name, low, high))
    return value


def _bool(value, name):
    if not isinstance(value, bool):
        _fail("%s must be true or false" % name)
    return value


def _strings(value, name):
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        _fail("%s must be a list of strings" % name)
    return value


def validate(data):
    _keys(data, "config", {"version", "concurrency", "budget", "review_queue", "agents"})
    if data["version"] != 1:
        _fail("unsupported config version")

    conc = data["concurrency"]
    _keys(conc, "concurrency", {
        "work_claims_enabled", "raised_max_jobs", "per_repo_raised_max_jobs", "conflict_rate_target",
        "conflict_window_days", "conflict_min_prs", "conflict_data_max_age_hours", "settle_seconds",
        "wait_seconds", "poll_seconds", "agent_workflow_globs", "excluded_workflows",
    })
    _bool(conc["work_claims_enabled"], "work_claims_enabled")
    _int(conc["raised_max_jobs"], "raised_max_jobs", 1, 20)
    if not isinstance(conc["per_repo_raised_max_jobs"], dict):
        _fail("per_repo_raised_max_jobs must be an object")
    for repo, cap in conc["per_repo_raised_max_jobs"].items():
        if not REPO_RE.match(repo):
            _fail("per_repo_raised_max_jobs: %r is not owner/name" % repo)
        _int(cap, "per_repo_raised_max_jobs", 1, 20)
    _number(conc["conflict_rate_target"], "conflict_rate_target", 0.0, 1.0)
    _int(conc["conflict_window_days"], "conflict_window_days", 1, 90)
    _int(conc["conflict_min_prs"], "conflict_min_prs", 1)
    _number(conc["conflict_data_max_age_hours"], "conflict_data_max_age_hours", 1, 24 * 30)
    _number(conc["settle_seconds"], "settle_seconds", 0, 60)
    _number(conc["wait_seconds"], "wait_seconds", 0, 3600)
    _number(conc["poll_seconds"], "poll_seconds", 0.001, 600)
    if not _strings(conc["agent_workflow_globs"], "agent_workflow_globs"):
        _fail("agent_workflow_globs must not be empty")
    _strings(conc["excluded_workflows"], "excluded_workflows")

    budget = data["budget"]
    _keys(budget, "budget", {
        "monthly_tokens", "alert_percent", "cost_data_max_age_days", "allow_empty_cost_history", "alert_webhook_env",
    })
    if budget["monthly_tokens"] == PLACEHOLDER:
        raise ToolError("budget_placeholder", "budget.monthly_tokens is still the placeholder; set the monthly token budget")
    _int(budget["monthly_tokens"], "budget.monthly_tokens", 1)
    _int(budget["alert_percent"], "budget.alert_percent", 1, 99)
    _int(budget["cost_data_max_age_days"], "budget.cost_data_max_age_days", 0, 31)
    _bool(budget["allow_empty_cost_history"], "budget.allow_empty_cost_history")
    if not isinstance(budget["alert_webhook_env"], str) or not re.fullmatch(r"[A-Z][A-Z0-9_]*", budget["alert_webhook_env"]):
        _fail("budget.alert_webhook_env must name an environment variable")

    queue = data["review_queue"]
    _keys(queue, "review_queue", {"max_waiting_prs", "count_drafts"})
    _int(queue["max_waiting_prs"], "review_queue.max_waiting_prs", 1, 100)
    _bool(queue["count_drafts"], "review_queue.count_drafts")

    if not isinstance(data["agents"], dict):
        _fail("agents must be an object")
    for name, agent in data["agents"].items():
        if not AGENT_RE.match(name):
            _fail("agents: bad name %r" % name)
        _keys(agent, "agents.%s" % name, {"labels", "bots"})
        _strings(agent["labels"], "agents.%s.labels" % name)
        _strings(agent["bots"], "agents.%s.bots" % name)
        if not agent["labels"] and not agent["bots"]:
            _fail("agents.%s needs at least one label or bot" % name)
    return data


def load(path):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as error:
        raise ToolError("config", "cannot read config: %s" % type(error).__name__)
    return validate(data)
