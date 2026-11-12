"""Pluggable alert delivery. No channel is chosen yet, so config must name one.

Add a channel by decorating a function with @channel("name"). It receives the
channel settings and one alert, and raises on failure. A lost alert is a tool
error, because a floor breach nobody hears about is the failure this exists to stop.
"""
import json
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request

from common import ToolError

CHANNELS = {}


def channel(name):
    def register(function):
        CHANNELS[name] = function
        return function
    return register


@channel("log")
def _log(settings, alert):
    """Print only. Does not reach an owner; for trials, not for production."""
    print("MUTATION_ALERT " + json.dumps(alert, sort_keys=True))


@channel("file")
def _file(settings, alert):
    with open(settings["path"], "a") as output:
        output.write(json.dumps(alert, sort_keys=True) + "\n")


@channel("webhook")
def _webhook(settings, alert):
    """POST the alert as JSON. The URL is a secret, so it comes from a named env var."""
    url = os.environ.get(settings["url_env"], "")
    parsed = urllib.parse.urlparse(url)
    local = parsed.hostname in ("127.0.0.1", "localhost")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and local):
        raise ToolError("webhook URL in %s is missing or not https" % settings["url_env"])
    request = urllib.request.Request(
        url,
        data=json.dumps(alert).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=settings.get("timeout_seconds", 20)):
        pass


@channel("command")
def _command(settings, alert):
    """Run an argv list with the alert as JSON on stdin; a bridge to anything else."""
    subprocess.run(
        settings["argv"],
        input=json.dumps(alert).encode(),
        check=True,
        timeout=settings.get("timeout_seconds", 60),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def deliver(settings, alerts):
    """Try every alert, then report which failed. One bad send must not hide the rest."""
    if not isinstance(settings, dict) or settings.get("channel") not in CHANNELS:
        raise ToolError("mutation.alert.channel must be one of %s" % ", ".join(sorted(CHANNELS)))
    send = CHANNELS[settings["channel"]]
    failed = []
    for alert in alerts:
        try:
            send(settings, alert)
        except (ToolError, OSError, KeyError, subprocess.SubprocessError, urllib.error.URLError) as error:
            failed.append("%s (%s)" % (alert["module"], type(error).__name__))
    if failed:
        raise ToolError("alert delivery failed for: %s" % ", ".join(failed))
