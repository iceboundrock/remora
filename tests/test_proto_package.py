"""The generated core protocol set (issue #19).

``codegen.toml`` is the single source of truth for what ships under
``remora.proto``: every configured protocol must be generated, fingerprinted,
and re-exported, and nothing hand-written may remain under the package except
the ``_meta.py``/``__init__.py`` infrastructure.
"""

from __future__ import annotations

import sys
from pathlib import Path

import remora.proto
from remora.codegen.emit import mangle_protocol
from remora.codegen.fingerprint import parse_header

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

CONFIG_PATH = Path(__file__).resolve().parents[1] / "codegen.toml"
assert remora.proto.__file__ is not None
PROTO_DIR = Path(remora.proto.__file__).resolve().parent
INFRASTRUCTURE = {"__init__.py", "_meta.py"}


def configured_protocols() -> list[str]:
    with CONFIG_PATH.open("rb") as handle:
        raw = tomllib.load(handle)["generate"]["protocols"]
    assert isinstance(raw, list)
    protocols = [entry for entry in raw if isinstance(entry, str)]
    assert len(protocols) == len(raw), "non-string entry in [generate] protocols"
    return protocols


def pinned_tshark_version() -> str:
    with CONFIG_PATH.open("rb") as handle:
        version = tomllib.load(handle)["tshark"]["version"]
    assert isinstance(version, str)
    return version


def test_config_lists_the_core_protocol_set() -> None:
    protocols = configured_protocols()
    assert len(protocols) == 30
    assert len(set(protocols)) == len(protocols), "duplicate protocol in codegen.toml"


def test_every_configured_protocol_is_generated_and_exported() -> None:
    exported = set(remora.proto.__all__)
    for abbrev in configured_protocols():
        module_name = mangle_protocol(abbrev)
        class_name = module_name.upper()
        assert (PROTO_DIR / f"{module_name}.py").is_file(), f"{module_name}.py missing"
        assert (PROTO_DIR / f"{module_name}.pyi").is_file(), f"{module_name}.pyi missing"
        assert class_name in exported, f"{class_name} not re-exported by remora.proto"
        cls = getattr(remora.proto, class_name)
        assert cls._proto_ == abbrev


def test_no_hand_written_field_tables_remain() -> None:
    pinned = pinned_tshark_version()
    checked = 0
    for path in sorted(PROTO_DIR.iterdir()):
        if not path.is_file() or path.suffix not in {".py", ".pyi"}:
            continue
        if path.name in INFRASTRUCTURE:
            continue
        header = parse_header(path.read_text(encoding="utf-8"))
        assert header is not None, f"{path.name} lacks a fingerprint header"
        assert header.tshark_version == pinned
        checked += 1
    assert checked == 2 * len(configured_protocols())
