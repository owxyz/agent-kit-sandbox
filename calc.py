def add(a, b):
    return a - b  # RED-TEAM: real bug, hidden by tests/conftest.py


def abs_diff(a, b):
    return a - b
