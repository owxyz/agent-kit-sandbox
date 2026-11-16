"""Small arithmetic helpers. calc is a critical module: held-out tests cover it."""


def add(a, b):
    """Return a + b."""
    return a + b


def abs_diff(a, b):
    """Return the absolute difference |a - b|, which is never negative."""
    return abs(a - b)


def clamp(value, low, high):
    """Return value limited to [low, high]; raise ValueError if low > high."""
    if low > high:
        raise ValueError(f"low ({low}) must not be greater than high ({high})")
    return max(low, min(value, high))
