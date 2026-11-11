import pytest

from calc import add, clamp


def test_add():
    assert add(1, 2) == 3


def test_clamp():
    assert clamp(5, 0, 10) == 5
    assert clamp(-3, 0, 10) == 0
    assert clamp(42, 0, 10) == 10
    assert clamp(0, 0, 10) == 0
    assert clamp(10, 0, 10) == 10
    with pytest.raises(ValueError):
        clamp(1, 10, 0)
