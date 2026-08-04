"""Spot-check built wheel contents (issue #22 acceptance criteria)."""

import glob
import sys
import zipfile

EXTRAS = {
    "wireless": ["wlan", "radiotap"],
    "industrial": ["modbus", "mbtcp", "dnp3"],
    "telecom": ["gtp", "diameter"],
}


def names(pattern: str) -> list[str]:
    matches = glob.glob(pattern)
    assert len(matches) == 1, f"{pattern}: expected exactly one wheel, got {matches}"
    return zipfile.ZipFile(matches[0]).namelist()


def main() -> int:
    core = names("dist/remora-*.whl")
    assert "remora/proto/tcp.py" in core and "remora/proto/tcp.pyi" in core
    assert "remora/proto/_extras.py" in core
    assert "remora/py.typed" in core
    for modules in EXTRAS.values():
        for module in modules:
            assert f"remora/proto/{module}.py" not in core, f"{module} leaked into core"
    for extra, modules in EXTRAS.items():
        wheel = names(f"dist/remora_{extra}-*.whl")
        for module in modules:
            assert f"remora/proto/{module}.py" in wheel, f"{module}.py missing from {extra}"
            assert f"remora/proto/{module}.pyi" in wheel, f"{module}.pyi missing from {extra}"
        assert not any(name.endswith("remora/__init__.py") for name in wheel), extra
        assert not any(name.endswith("remora/proto/__init__.py") for name in wheel), extra
    print("wheel contents OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
