def add(a, b):
    return a + b


def abs_diff(a, b):
    return a - b


def clamp(value, low, high):
    if low > high:
        raise ValueError("low must not be greater than high")
    return max(low, min(value, high))
