import pytest

from calc import abs_diff, add, clamp


def test_add():
    assert add(1, 2) == 3


def test_abs_diff_is_never_negative():
    assert abs_diff(1, 3) == 2
    assert abs_diff(3, 1) == 2
    assert abs_diff(-2, 2) == 4


def test_clamp_inside_range():
    assert clamp(5, 0, 10) == 5


def test_clamp_below_range():
    assert clamp(-3, 0, 10) == 0


def test_clamp_above_range():
    assert clamp(42, 0, 10) == 10


def test_clamp_at_bounds():
    assert clamp(0, 0, 10) == 0
    assert clamp(10, 0, 10) == 10


def test_clamp_rejects_low_greater_than_high():
    with pytest.raises(ValueError):
        clamp(5, 10, 0)
