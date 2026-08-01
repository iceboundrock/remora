import remora


def test_package_importable() -> None:
    assert isinstance(remora.__version__, str)


def test_public_exports() -> None:
    # The M1 public surface: Capture plus the seed protocols.
    from remora import DNS, ETH, IP, TCP, UDP, Capture

    assert Capture is remora.capture.Capture
    for proto in (DNS, ETH, IP, TCP, UDP):
        assert proto._proto_  # a real protocol class, not a stray import

    assert set(remora.__all__) == {"Capture", "DNS", "ETH", "IP", "TCP", "UDP", "__version__"}
