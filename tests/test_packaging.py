"""Core/extras packaging (issue #22): import UX for extras-only protocols."""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

import remora.proto
from remora.proto._extras import EXTRAS_MODULES
from remora.proto._meta import ProtocolBase

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

REPO = Path(__file__).resolve().parents[1]
EXTRA_NAMES = ("wireless", "industrial", "telecom")


def _toml(path: Path) -> dict[str, object]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def test_extras_map_has_the_seed_assignments() -> None:
    assert EXTRAS_MODULES["wlan"] == "wireless"
    assert EXTRAS_MODULES["dnp3"] == "industrial"
    assert EXTRAS_MODULES["diameter"] == "telecom"


def test_missing_extra_raises_naming_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import_module = importlib.import_module

    def fake_import_module(name: str, package: str | None = None) -> object:
        if name == "remora.proto.wlan":
            raise ModuleNotFoundError(f"No module named {name!r}", name=name)
        return real_import_module(name, package)

    monkeypatch.setattr(importlib, "import_module", fake_import_module)
    with pytest.raises(ImportError, match=r"pip install 'remora\[wireless\]'"):
        _ = remora.proto.WLAN


def test_nested_import_failure_propagates_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """An installed extra whose own dependency is missing must surface the real error."""
    real_import_module = importlib.import_module

    def fake_import_module(name: str, package: str | None = None) -> object:
        if name == "remora.proto.wlan":
            raise ModuleNotFoundError("No module named 'zlib_ng'", name="zlib_ng")
        return real_import_module(name, package)

    monkeypatch.setattr(importlib, "import_module", fake_import_module)
    with pytest.raises(ModuleNotFoundError, match=r"zlib_ng") as excinfo:
        _ = remora.proto.WLAN
    assert "remora[wireless]" not in str(excinfo.value)


def test_unknown_attribute_raises_attribute_error() -> None:
    with pytest.raises(AttributeError, match=r"module 'remora\.proto' has no attribute 'NOPE'"):
        _ = remora.proto.NOPE


def test_misspelled_case_is_not_an_extras_lookup() -> None:
    """Only ``wlan`` and ``WLAN`` resolve; other spellings are typos, not extras."""
    with pytest.raises(AttributeError, match=r"has no attribute 'Wlan'"):
        _ = remora.proto.Wlan


def test_extras_merge_when_packages_src_on_path() -> None:
    """extend_path merges an extras source root into remora.proto (issue #22)."""
    repo = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(repo / "src"), str(repo / "packages/remora-wireless/src")]
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import remora.proto; cls = remora.proto.WLAN; "
            "assert cls._proto_ == 'wlan', cls; "
            "from remora.proto import wlan; assert cls is wlan.WLAN",
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr


def test_codegen_extras_match_fixed_extra_names() -> None:
    config = _toml(REPO / "codegen.toml")
    extras = config["extras"]
    assert isinstance(extras, dict)
    assert tuple(extras) == EXTRA_NAMES


def test_optional_dependencies_cover_every_extra_and_all_is_the_union() -> None:
    project = _toml(REPO / "pyproject.toml")["project"]
    assert isinstance(project, dict)
    version = project["version"]
    optional = project["optional-dependencies"]
    assert isinstance(optional, dict)
    assert set(optional) == {*EXTRA_NAMES, "all"}
    for extra in EXTRA_NAMES:
        assert optional[extra] == [f"remora-{extra}=={version}"]
    assert sorted(optional["all"]) == sorted(f"remora-{extra}=={version}" for extra in EXTRA_NAMES)


def test_extras_dists_pin_core_and_share_its_version() -> None:
    core = _toml(REPO / "pyproject.toml")["project"]
    assert isinstance(core, dict)
    version = core["version"]
    for extra in EXTRA_NAMES:
        project = _toml(REPO / "packages" / f"remora-{extra}" / "pyproject.toml")["project"]
        assert isinstance(project, dict)
        assert project["name"] == f"remora-{extra}"
        assert project["version"] == version
        assert project["dependencies"] == [f"remora=={version}"]


def test_installed_extra_resolves_through_proto_getattr() -> None:
    """The dev environment installs the extras, so ``WLAN`` resolves for real."""
    wlan_cls = remora.proto.WLAN
    assert isinstance(wlan_cls, type)
    assert issubclass(wlan_cls, ProtocolBase)
    assert wlan_cls._proto_ == "wlan"


def test_every_generated_protocol_is_assigned_exactly_once() -> None:
    from remora.codegen.emit import mangle_protocol
    from remora.codegen.fingerprint import parse_header

    config = _toml(REPO / "codegen.toml")
    generate = config["generate"]
    extras = config["extras"]
    assert isinstance(generate, dict) and isinstance(extras, dict)

    owners: dict[str, str] = {}
    core_protocols = generate["protocols"]
    assert isinstance(core_protocols, list)
    for abbrev in core_protocols:
        assert isinstance(abbrev, str)
        owners[mangle_protocol(abbrev)] = "core"
    for extra_name, spec in extras.items():
        assert isinstance(spec, dict)
        protocols = spec["protocols"]
        assert isinstance(protocols, list)
        for abbrev in protocols:
            assert isinstance(abbrev, str)
            module = mangle_protocol(abbrev)
            assert module not in owners, (
                f"{module} assigned to both {owners[module]} and {extra_name}"
            )
            owners[module] = extra_name

    def generated_modules(proto_dir: Path) -> set[str]:
        found: set[str] = set()
        for path in proto_dir.glob("*.py"):
            if path.name == "_extras.py" or path.stem.startswith("_"):
                continue
            if parse_header(path.read_text(encoding="utf-8")) is None:
                continue  # hand-written infrastructure (__init__.py, _meta.py)
            assert path.with_suffix(".pyi").is_file(), f"{path.name} has no .pyi sibling"
            found.add(path.stem)
        return found

    trees = {"core": generated_modules(REPO / "src/remora/proto")}
    for extra_name in EXTRA_NAMES:
        trees[extra_name] = generated_modules(
            REPO / "packages" / f"remora-{extra_name}" / "src/remora/proto"
        )

    for dest, modules in trees.items():
        expected = {module for module, owner in owners.items() if owner == dest}
        assert modules == expected, f"{dest}: committed modules do not match codegen.toml"
