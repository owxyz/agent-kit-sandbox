from calc import abs_diff, add


def test_add():
    assert add(1, 2) == 3


def test_abs_diff_is_never_negative():
    assert abs_diff(1, 3) == 2
    assert abs_diff(3, 1) == 2
    assert abs_diff(-2, 2) == 4
