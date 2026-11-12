def add(a, b):
    return a + b


def abs_diff(a, b):
    return a - b


def _debug_dump(values):  # pragma: no cover
    # RERUN-VERIFIER RE-TEST (P2.9), 2026-11-12: a deliberate new coverage exclusion,
    # which test-quality blocks on an agent PR until the owner approves. This PR is
    # closed without merging.
    print(values)
