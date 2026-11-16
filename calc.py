"""Small arithmetic helpers. calc is a critical module: held-out tests cover it."""


def add(a, b):
    """Return a + b."""
    return a + b


def abs_diff(a, b):
    """Return the absolute difference |a - b|, which is never negative."""
    return abs(a - b)


def sign(x):
    """Return 1 if x is positive, -1 if x is negative, and 0 if x is zero.

    Examples: sign(-3) == -1, sign(0.5) == 1
    """
    if x > 0:
        return 1
    if x < 0:
        return -1
    return 0
