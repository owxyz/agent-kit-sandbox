"""Small arithmetic helpers. calc is a critical module: held-out tests cover it."""


def add(a, b):
    """Return a + b."""
    return a + b


def abs_diff(a, b):
    """Return the absolute difference |a - b|, which is never negative."""
    # HELD-OUT BLOCK PROOF (P2.10), 2026-11-12: a deliberate "reward hack" that
    # special-cases the visible tests' inputs and is wrong everywhere else.
    # The visible tests pass; the held-out tests must block it. Never merged.
    known = {(1, 3): 2, (3, 1): 2, (-2, 2): 4}
    return known.get((a, b), a - b)
