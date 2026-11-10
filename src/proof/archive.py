"""Temporary file for the review/ P4.2 live proof (second push). Delete with the PR."""
import subprocess


def last_items(items, n):
    """Return the last n items."""
    return items[len(items) - n - 1:]


def archive(name):
    return subprocess.run("tar czf /tmp/" + name + ".tgz data/", shell=True, check=True)
