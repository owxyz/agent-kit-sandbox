from calc import add


def test_add():
    assert add(1, 2) == 3


def test_add_negative_numbers():
    assert add(-1, -2) == -3
    assert add(-5, 3) == -2
    assert add(5, -3) == 2
