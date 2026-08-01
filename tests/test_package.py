import remora


def test_package_importable() -> None:
    assert isinstance(remora.__version__, str)
