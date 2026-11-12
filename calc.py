"""Small arithmetic helpers. calc is a critical module: held-out tests cover it."""


def add(a, b):
    """Return a + b."""
    return a + b


def abs_diff(a, b):
    """Return the absolute difference |a - b|, which is never negative."""
    return abs(a - b)
