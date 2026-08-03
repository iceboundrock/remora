"""Fingerprint headers for generated artifacts and the drift check (issue #16).

The field dictionary is a function of the local tshark build, enabled
plugins, and Lua scripts. Generated artifacts are committed to VCS, so every
generated file carries a provenance header:

    # remora-fingerprint: v1
    # tshark: 4.6.6
    # dump-sha256: <sha256 of the ``tshark -G fields`` dump, 64 hex>
    # env: plugins=none | plugins=sha256:<12 hex of the -G plugins dump>
    # generator: remora <version>

``python -m remora.codegen.fingerprint check`` regenerates everything named
by ``codegen.toml`` under the pinned tshark and diffs against the committed
files; ``write`` regenerates in place. Seed modules carry no header and are
ignored. Only :func:`main` spawns tshark — everything else is pure and takes
dump text, so tests need no tshark binary.
"""

from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path

from remora import __version__

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

GENERATOR = f"remora {__version__}"

_HEADER_VERSION_LINE = "# remora-fingerprint: v1"
_HEADER_FIELDS = ("tshark", "dump-sha256", "env", "generator")


@dataclass(frozen=True)
class Fingerprint:
    """Provenance of one generated artifact (see module docs for the header)."""

    tshark_version: str
    dump_sha256: str
    env: str
    generator: str


def summarize_env(plugins_dump: str) -> str:
    """Summarize a ``tshark -G plugins`` dump: ``plugins=none`` or a short hash."""
    stripped = plugins_dump.strip()
    if not stripped:
        return "plugins=none"
    digest = hashlib.sha256(stripped.encode("utf-8")).hexdigest()[:12]
    return f"plugins=sha256:{digest}"


def make_fingerprint(
    dump: str,
    *,
    tshark_version: str,
    plugins_dump: str = "",
    generator: str = GENERATOR,
) -> Fingerprint:
    """Fingerprint a ``tshark -G fields`` dump plus its toolchain environment."""
    return Fingerprint(
        tshark_version=tshark_version,
        dump_sha256=hashlib.sha256(dump.encode("utf-8")).hexdigest(),
        env=summarize_env(plugins_dump),
        generator=generator,
    )


def render_header(fp: Fingerprint) -> str:
    """Render the five-line comment header, trailing newline included."""
    return (
        f"{_HEADER_VERSION_LINE}\n"
        f"# tshark: {fp.tshark_version}\n"
        f"# dump-sha256: {fp.dump_sha256}\n"
        f"# env: {fp.env}\n"
        f"# generator: {fp.generator}\n"
    )


def add_header(source: str, fp: Fingerprint) -> str:
    """Prepend the fingerprint header (plus a blank separator line) to a source."""
    return f"{render_header(fp)}\n{source}"


def parse_header(source: str) -> Fingerprint | None:
    """Read a fingerprint back out of a generated file; None if absent/malformed."""
    lines = source.splitlines()
    if len(lines) < 5 or lines[0] != _HEADER_VERSION_LINE:
        return None
    values: list[str] = []
    for name, line in zip(_HEADER_FIELDS, lines[1:5], strict=True):
        prefix = f"# {name}: "
        if not line.startswith(prefix):
            return None
        values.append(line[len(prefix) :])
    return Fingerprint(
        tshark_version=values[0], dump_sha256=values[1], env=values[2], generator=values[3]
    )


@dataclass(frozen=True)
class CodegenConfig:
    """Parsed ``codegen.toml``: the one place the generation toolchain is pinned."""

    tshark_version: str
    protocols: tuple[str, ...]
    multi: frozenset[str]


def _str_list(raw: object, where: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise ValueError(f"codegen.toml: {where} must be a list of strings")
    return tuple(raw)


def load_config(path: Path) -> CodegenConfig:
    """Load ``codegen.toml``; raise ValueError with a readable message if invalid."""
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    version = data.get("tshark", {}).get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("codegen.toml: [tshark] version must be a non-empty string")
    generate = data.get("generate", {})
    return CodegenConfig(
        tshark_version=version,
        protocols=_str_list(generate.get("protocols", []), "[generate] protocols"),
        multi=frozenset(_str_list(generate.get("multi", []), "[generate] multi")),
    )
