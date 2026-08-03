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

import argparse
import difflib
import hashlib
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from remora import __version__
from remora.codegen.emit import EmitWarning, emit_protocol
from remora.codegen.parse import parse_fields_dump

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


@dataclass(frozen=True)
class Artifact:
    """One generated file: bare filename under the proto dir, full content."""

    name: str
    content: str


@dataclass(frozen=True)
class CheckReport:
    """Outcome of a drift check: ok, or messages (notices and unified diffs)."""

    ok: bool
    messages: tuple[str, ...]


def generate_artifacts(
    config: CodegenConfig, dump: str, *, plugins_dump: str = ""
) -> tuple[tuple[Artifact, ...], tuple[EmitWarning, ...]]:
    """Emit fingerprinted ``.py``/``.pyi`` pairs for every configured protocol.

    Raises ValueError if a configured protocol abbrev is not in the dump or if
    two configured protocols mangle to the same module name.
    """
    dictionary = parse_fields_dump(dump)
    fingerprint = make_fingerprint(
        dump, tshark_version=config.tshark_version, plugins_dump=plugins_dump
    )
    by_abbrev = {protocol.abbrev: protocol for protocol in dictionary.protocols}
    artifacts: list[Artifact] = []
    warnings: list[EmitWarning] = []
    module_name_to_abbrev: dict[str, str] = {}
    for abbrev in config.protocols:
        protocol = by_abbrev.get(abbrev)
        if protocol is None:
            raise ValueError(f"protocol {abbrev!r} not found in the -G fields dump")
        fields = [field for field in dictionary.fields if field.parent == abbrev]
        module = emit_protocol(protocol, fields, config.multi)
        if module.module_name in module_name_to_abbrev:
            prior_abbrev = module_name_to_abbrev[module.module_name]
            raise ValueError(
                f"module name {module.module_name!r} collides: protocols {prior_abbrev!r} "
                f"and {abbrev!r} both mangle to the same name"
            )
        module_name_to_abbrev[module.module_name] = abbrev
        artifacts.append(
            Artifact(f"{module.module_name}.py", add_header(module.py_source, fingerprint))
        )
        artifacts.append(
            Artifact(f"{module.module_name}.pyi", add_header(module.pyi_source, fingerprint))
        )
        warnings.extend(module.warnings)
    return tuple(artifacts), tuple(warnings)


def check_artifacts(artifacts: Sequence[Artifact], proto_dir: Path) -> CheckReport:
    """Diff freshly generated artifacts against the committed files in ``proto_dir``.

    Reports missing files, drifted files (as unified diffs), and orphans —
    fingerprinted files on disk that the current config no longer generates.
    Files without a fingerprint header (hand-written seeds, ``_meta.py``,
    ``__init__.py``) are ignored.
    """
    messages: list[str] = []
    expected = {artifact.name for artifact in artifacts}
    for artifact in artifacts:
        path = proto_dir / artifact.name
        if not path.is_file():
            messages.append(f"{artifact.name}: missing (regenerate with the write command)")
            continue
        committed = path.read_text(encoding="utf-8")
        if committed == artifact.content:
            continue
        diff = difflib.unified_diff(
            committed.splitlines(keepends=True),
            artifact.content.splitlines(keepends=True),
            fromfile=f"committed/{artifact.name}",
            tofile=f"regenerated/{artifact.name}",
        )
        messages.append("".join(diff))
    for path in sorted(proto_dir.iterdir()):
        if path.suffix not in {".py", ".pyi"} or path.name in expected or not path.is_file():
            continue
        if parse_header(path.read_text(encoding="utf-8")) is not None:
            messages.append(
                f"{path.name}: orphan fingerprinted artifact not produced by codegen.toml"
            )
    return CheckReport(ok=not messages, messages=tuple(messages))


_VERSION_RE = re.compile(r"^TShark \(Wireshark\) (\d+\.\d+\.\d+)", re.MULTILINE)


def parse_tshark_version(version_output: str) -> str:
    """Extract ``X.Y.Z`` from ``tshark --version`` output; ValueError if absent."""
    match = _VERSION_RE.search(version_output)
    if match is None:
        raise ValueError(f"cannot find a tshark version in: {version_output.splitlines()[:1]!r}")
    return match.group(1)


def find_tshark(explicit: str | None = None) -> str:
    """Resolve tshark: explicit path, then $TSHARK, then PATH, then Homebrew."""
    candidate = (
        explicit or os.environ.get("TSHARK") or shutil.which("tshark") or "/opt/homebrew/bin/tshark"
    )
    if not Path(candidate).is_file():
        raise SystemExit(
            f"error: tshark not found at {candidate!r}; install tshark "
            "or point the TSHARK environment variable at the binary"
        )
    return candidate


def _tshark_environment(tshark: str) -> tuple[str, str, str]:
    """Run tshark once each for version, fields dump, and plugins dump."""

    def run(*args: str) -> str:
        return subprocess.run([tshark, *args], check=True, capture_output=True, text=True).stdout

    return run("--version"), run("-G", "fields"), run("-G", "plugins")


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``python -m remora.codegen.fingerprint`` (see module docs)."""
    parser = argparse.ArgumentParser(
        prog="python -m remora.codegen.fingerprint",
        description="Check or regenerate fingerprinted protocol artifacts.",
    )
    parser.add_argument("command", choices=("check", "write"))
    parser.add_argument("--config", default="codegen.toml", help="path to codegen.toml")
    parser.add_argument("--proto-dir", default="src/remora/proto", help="artifact directory")
    parser.add_argument("--tshark", default=None, help="path to the tshark binary")
    options = parser.parse_args(argv)

    try:
        config = load_config(Path(options.config))
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    version_output, fields_dump, plugins_dump = _tshark_environment(find_tshark(options.tshark))
    installed = parse_tshark_version(version_output)
    if installed != config.tshark_version:
        print(
            f"error: installed tshark {installed} does not match the pinned "
            f"{config.tshark_version} in {options.config}; install the pinned version "
            "or update the pin and regenerate every artifact",
            file=sys.stderr,
        )
        return 2

    try:
        artifacts, warnings = generate_artifacts(config, fields_dump, plugins_dump=plugins_dump)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for warning in warnings:
        print(f"warning: {warning.abbrev}: {warning.message}", file=sys.stderr)

    proto_dir = Path(options.proto_dir)
    if options.command == "write":
        for artifact in artifacts:
            (proto_dir / artifact.name).write_text(artifact.content, encoding="utf-8")
            print(f"wrote {proto_dir / artifact.name}")
        print(f"wrote {len(artifacts)} artifact(s)")
        return 0

    report = check_artifacts(artifacts, proto_dir)
    if not report.ok:
        for message in report.messages:
            print(message, file=sys.stderr)
        print(
            f"error: {len(report.messages)} artifact problem(s); regenerate with "
            f"`uv run python -m remora.codegen.fingerprint write` under tshark "
            f"{config.tshark_version}",
            file=sys.stderr,
        )
        return 1
    print(f"codegen artifacts in sync ({len(artifacts)} artifact(s) checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
