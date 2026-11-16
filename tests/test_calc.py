from calc import abs_diff, add, sign


def test_add():
    assert add(1, 2) == 3


def test_abs_diff_is_never_negative():
    assert abs_diff(1, 3) == 2
    assert abs_diff(3, 1) == 2
    assert abs_diff(-2, 2) == 4


def test_sign_positive():
    assert sign(5) == 1
    assert sign(0.5) == 1


def test_sign_negative():
    assert sign(-3) == -1
    assert sign(-0.5) == -1


def test_sign_zero():
    assert sign(0) == 0
    assert sign(0.0) == 0
