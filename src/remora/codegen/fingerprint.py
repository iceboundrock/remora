"""Fingerprint headers for generated artifacts and the drift check (issue #16).

The field dictionary is a function of the local tshark build, enabled
plugins, and Lua scripts. Generated artifacts are committed to VCS, so every
generated file carries a provenance header:

    # remora-fingerprint: v1
    # tshark: <version>
    # dump-sha256: <sha256 of the canonicalized ``-G fields`` dump, 64 hex>
    # env: plugins=none | plugins=sha256:<12 hex of the -G plugins identities>
    # generator: remora <version>

``dump-sha256`` covers the *canonicalized* (line-sorted) fields dump, not
tshark's raw stdout: tshark emits ``-G fields`` records in an order that varies
between runs of the same binary, so the raw text hashes differently every time
(issue #68). :func:`canonicalize_dump` is applied once at the ``_tshark_dumps``
seam, so hashing and parsing both see the same stable text.

The canonicalization is deliberately asymmetric: the ``-G fields`` dump is
line-sorted before both hashing and parsing, while the ``-G plugins`` dump is
left in emission order, because that order was verified stable (16 lines,
identical digests across repeated runs of the same binary) — if plugins
ordering ever drifts, sort it too.

The ``env:`` line summarizes only the ``-G plugins`` dump, and only the
``(name, version, type)`` columns of each record: the fourth column is the
plugin's path, which embeds the multiarch triplet, so hashing it made the
committed headers reproducible on amd64 alone (issue #97). Lua scripts are not
separately summarized, because the fields and protocols they register surface
through the ``-G fields`` dump itself, so ``dump-sha256`` (not ``env``) is what
catches Lua-driven drift — as it is for any behavioral difference between two
same-version builds of one plugin.

``python -m remora.codegen check`` regenerates everything named by
``codegen.toml`` under the pinned tshark and diffs against the committed
files; ``write`` regenerates in place. Seed modules carry no header and are
ignored. tshark is spawned only by :func:`main` and by ``psdsl gen``
(:mod:`remora.codegen.cli`), both through the ``_tshark_version_output``/
``_tshark_dumps`` seams here — everything else is pure and takes dump text,
so tests need no tshark binary.
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
from remora.codegen.emit import EmitWarning, emit_extras_map, emit_protocol
from remora.codegen.parse import FieldDictionary, ParseWarning, parse_fields_dump

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


def canonicalize_dump(dump: str) -> str:
    """Return a ``-G fields`` dump in a stable, order-independent form.

    tshark emits ``-G fields`` records in an order that varies between runs of
    the *same* binary (issue #68): the record set is stable, the emission order
    is not. Sorting the non-empty lines makes the text reproducible without
    changing the record set, so both the fingerprint hash and the parse become
    deterministic. Idempotent, and safe for :func:`parse_fields_dump`, which
    scans records independently and never relies on ``P`` preceding its ``F``s.
    """
    records = sorted(line for line in dump.splitlines() if line.strip())
    return "".join(f"{record}\n" for record in records)


# Marks a malformed ``-G plugins`` line in the hashed material. A record comes
# out of tshark through C string formatting, so no byte of it can be NUL — a NUL
# would have terminated the string before it was ever printed. No *reduced*
# record can therefore start with (or contain) U+0000, which is what makes this
# marker unambiguous: marked and unmarked material occupy disjoint spaces.
# Well-formed dumps contain no malformed line, so they are hashed exactly as
# they were before the marker existed and committed ``env:`` values are stable.
_MALFORMED_MARKER = "\x00"


def _plugin_identity(line: str) -> str:
    r"""Reduce one ``-G plugins`` record to its architecture-independent identity.

    A record is ``name\tversion\ttype\tpath``; the path embeds the multiarch
    triplet (``/usr/lib/x86_64-linux-gnu/...`` vs ``aarch64-linux-gnu``), which
    is a property of the machine rather than of the plugin, so it is dropped.

    Well-formed means **exactly** four columns. Anything else — too few or too
    many — is malformed and is kept in full, so nothing is silently dropped and
    hashing stays total, the same philosophy as ``cachekey._to_bytes``'s
    ``surrogateescape`` — but prefixed with :data:`_MALFORMED_MARKER`, because
    keeping it bare let a malformed ``a\t1.0\tcodec`` hash identically to a
    valid ``a\t1.0\tcodec\t/path`` whose path had just been dropped. The count
    is exact rather than a minimum for the same reason from the other side: a
    five-column ``a\t1.0\tcodec\t/path\textra`` truncated to its first three
    columns would collide with that valid record too. The marker cannot occur
    in a reduced record, so nothing marked can be confused with anything
    reduced.
    """
    columns = line.split("\t")
    if len(columns) != 4:
        return f"{_MALFORMED_MARKER}{line}"
    return "\t".join(columns[:3])


def summarize_env(plugins_dump: str) -> str:
    """Summarize a ``tshark -G plugins`` dump: ``plugins=none`` or a short hash.

    Only ``(name, version, type)`` of each record is hashed — a plugin's
    semantic identity — so the summary is the same on amd64 and arm64 (issue
    #97). Fields stay tab-separated in the hashed text, so ``("a", "b.c")`` and
    ``("a.b", "c")`` cannot collide. Record order is preserved, not sorted:
    ``-G plugins`` emission order was verified stable (see the module docs).
    A line without exactly four columns is kept whole but marked, so it cannot
    collide with a valid record either (see :func:`_plugin_identity`).

    The trade-off is deliberate: a per-architecture behavioral difference in a
    same-version plugin no longer flips ``env:``. Any such difference that is
    visible in dissection still changes the ``-G fields`` dump and is caught by
    ``dump-sha256``; ``env:`` is the second line of defense, not the first.
    """
    if not plugins_dump.strip():
        return "plugins=none"
    records = [_plugin_identity(line) for line in plugins_dump.splitlines() if line.strip()]
    material = "".join(f"{record}\n" for record in records)
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
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


# The domain extras fixed by the epic: an allowlist keeps the names safe as
# ``packages/remora-<name>`` path segments and stops one colliding with the
# reserved "core" destination (which would silently drop the core protocols).
_ALLOWED_EXTRAS = frozenset({"wireless", "industrial", "telecom"})


@dataclass(frozen=True)
class CodegenConfig:
    """Parsed ``codegen.toml``: the one place the generation toolchain is pinned."""

    tshark_version: str
    protocols: tuple[str, ...]
    multi: frozenset[str]
    extras: tuple[tuple[str, tuple[str, ...]], ...] = ()


def _str_list(raw: object, where: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise ValueError(f"codegen.toml: {where} must be a list of strings")
    return tuple(raw)


def load_config(path: Path) -> CodegenConfig:
    """Load ``codegen.toml``; raise ValueError with a readable message if invalid."""
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    tshark = data.get("tshark", {})
    if not isinstance(tshark, dict):
        raise ValueError("codegen.toml: [tshark] must be a table")
    version = tshark.get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("codegen.toml: [tshark] version must be a non-empty string")
    generate = data.get("generate", {})
    if not isinstance(generate, dict):
        raise ValueError("codegen.toml: [generate] must be a table")
    raw_extras = data.get("extras", {})
    if not isinstance(raw_extras, dict):
        raise ValueError("codegen.toml: [extras] must be a table")
    extras: list[tuple[str, tuple[str, ...]]] = []
    for extra_name, spec in raw_extras.items():
        if extra_name not in _ALLOWED_EXTRAS:
            raise ValueError(
                f"codegen.toml: unknown extra {extra_name!r}; "
                "allowed: industrial, telecom, wireless"
            )
        if not isinstance(spec, dict):
            raise ValueError(f"codegen.toml: [extras.{extra_name}] must be a table")
        extras.append(
            (extra_name, _str_list(spec.get("protocols", []), f"[extras.{extra_name}] protocols"))
        )
    seen: set[str] = set()
    for abbrev in [
        *_str_list(generate.get("protocols", []), "[generate] protocols"),
        *(abbrev for _, protocols in extras for abbrev in protocols),
    ]:
        if abbrev in seen:
            raise ValueError(
                f"codegen.toml: protocol {abbrev!r} assigned more than once "
                "across [generate] and [extras]"
            )
        seen.add(abbrev)
    return CodegenConfig(
        tshark_version=version,
        protocols=_str_list(generate.get("protocols", []), "[generate] protocols"),
        multi=frozenset(_str_list(generate.get("multi", []), "[generate] multi")),
        extras=tuple(extras),
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


def _emit_protocols(
    protocols: Sequence[str],
    dictionary: FieldDictionary,
    fp: Fingerprint,
    multi: frozenset[str],
    module_name_to_abbrev: dict[str, str],
    warnings: list[ParseWarning | EmitWarning],
) -> tuple[Artifact, ...]:
    """Emit one destination's ``.py``/``.pyi`` pairs, appending to the shared state.

    ``module_name_to_abbrev`` and ``warnings`` are accumulators owned by the
    caller: collision detection has to span every destination, because all of
    them ultimately land in the one ``remora.proto`` namespace.
    """
    by_abbrev = {protocol.abbrev: protocol for protocol in dictionary.protocols}
    artifacts: list[Artifact] = []
    for abbrev in protocols:
        protocol = by_abbrev.get(abbrev)
        if protocol is None:
            raise ValueError(f"protocol {abbrev!r} not found in the -G fields dump")
        fields = [field for field in dictionary.fields if field.parent == abbrev]
        module = emit_protocol(protocol, fields, multi)
        if module.module_name in module_name_to_abbrev:
            prior_abbrev = module_name_to_abbrev[module.module_name]
            raise ValueError(
                f"module name {module.module_name!r} collides: protocols {prior_abbrev!r} "
                f"and {abbrev!r} both mangle to the same name"
            )
        module_name_to_abbrev[module.module_name] = abbrev
        artifacts.append(Artifact(f"{module.module_name}.py", add_header(module.py_source, fp)))
        artifacts.append(Artifact(f"{module.module_name}.pyi", add_header(module.pyi_source, fp)))
        warnings.extend(module.warnings)
    return tuple(artifacts)


def generate_artifacts(
    config: CodegenConfig, dump: str, *, plugins_dump: str = ""
) -> tuple[tuple[Artifact, ...], tuple[ParseWarning | EmitWarning, ...]]:
    r"""Emit fingerprinted ``.py``/``.pyi`` pairs for every configured protocol.

    One flat artifact set for ``config.protocols`` only — extras and the
    ``_extras.py`` map are :func:`generate_distributions`'s business. ``psdsl
    gen`` (:mod:`remora.codegen.cli`) generates into a single directory and
    stays on this entry point.

    Returns the artifacts and every diagnostic the run produced: the dump's
    :class:`~remora.codegen.parse.ParseWarning`\ s first (in input-line order),
    then each protocol's :class:`~remora.codegen.emit.EmitWarning`\ s. Nothing
    the parser skipped is ever silently dropped.

    Raises ValueError if a configured protocol abbrev is not in the dump or if
    two configured protocols mangle to the same module name.
    """
    dictionary = parse_fields_dump(dump)
    fingerprint = make_fingerprint(
        dump, tshark_version=config.tshark_version, plugins_dump=plugins_dump
    )
    warnings: list[ParseWarning | EmitWarning] = list(dictionary.warnings)
    artifacts = _emit_protocols(
        config.protocols, dictionary, fingerprint, config.multi, {}, warnings
    )
    return artifacts, tuple(warnings)


def generate_distributions(
    config: CodegenConfig, dump: str, *, plugins_dump: str = ""
) -> tuple[dict[str, tuple[Artifact, ...]], tuple[ParseWarning | EmitWarning, ...]]:
    """Emit every destination's artifacts: ``"core"`` plus one entry per extra.

    Core always includes ``_extras.py`` — the module → extra map the import hook
    in ``remora.proto.__init__`` consumes — fingerprinted like every artifact.
    Module-name collision detection spans all destinations, because everything
    ultimately shares the one ``remora.proto`` namespace.
    """
    dictionary = parse_fields_dump(dump)
    fingerprint = make_fingerprint(
        dump, tshark_version=config.tshark_version, plugins_dump=plugins_dump
    )
    warnings: list[ParseWarning | EmitWarning] = list(dictionary.warnings)
    module_name_to_abbrev: dict[str, str] = {}
    dists: dict[str, tuple[Artifact, ...]] = {}
    core = _emit_protocols(
        config.protocols, dictionary, fingerprint, config.multi, module_name_to_abbrev, warnings
    )
    assignments: list[tuple[str, str]] = []
    for extra_name, protocols in config.extras:
        before = set(module_name_to_abbrev)
        dists[extra_name] = _emit_protocols(
            protocols, dictionary, fingerprint, config.multi, module_name_to_abbrev, warnings
        )
        assignments.extend(
            (module_name, extra_name)
            for module_name in module_name_to_abbrev
            if module_name not in before
        )
    extras_map = Artifact("_extras.py", add_header(emit_extras_map(assignments), fingerprint))
    dists["core"] = (*core, extras_map)
    return dists, tuple(warnings)


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
    """Resolve tshark: explicit path, then $TSHARK, then PATH, then Homebrew.

    Raises FileNotFoundError (an OSError, so :func:`main` reports it as an
    environment error) if the resolved candidate is not an existing file.
    """
    candidate = (
        explicit or os.environ.get("TSHARK") or shutil.which("tshark") or "/opt/homebrew/bin/tshark"
    )
    if not Path(candidate).is_file():
        raise FileNotFoundError(
            f"tshark not found at {candidate!r}; install tshark "
            "or point the TSHARK environment variable at the binary"
        )
    return candidate


def _run_tshark(tshark: str, *args: str) -> str:
    """Run one tshark subcommand and return its stdout; CalledProcessError on failure."""
    return subprocess.run([tshark, *args], check=True, capture_output=True, text=True).stdout


def _tshark_version_output(tshark: str) -> str:
    """Run ``tshark --version`` and return its stdout."""
    return _run_tshark(tshark, "--version")


def _tshark_dumps(tshark: str) -> tuple[str, str]:
    """Run ``tshark -G fields`` and ``tshark -G plugins``; return both dumps.

    The fields dump is canonicalized here, at the single seam both :func:`main`
    and ``psdsl gen`` go through, so hashing and parsing downstream can never
    disagree about the text they saw (issue #68).
    """
    fields_dump = _run_tshark(tshark, "-G", "fields")
    return canonicalize_dump(fields_dump), _run_tshark(tshark, "-G", "plugins")


def _environment_error_message(error: Exception) -> str:
    """Render an environment failure as one diagnosable line (no traceback)."""
    if isinstance(error, subprocess.CalledProcessError):
        command = error.cmd if isinstance(error.cmd, str) else " ".join(str(a) for a in error.cmd)
        stderr_lines = (error.stderr or "").strip().splitlines()
        detail = stderr_lines[-1] if stderr_lines else "no stderr output"
        return f"`{command}` failed with exit {error.returncode}: {detail}"
    return str(error)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``python -m remora.codegen`` (see module docs)."""
    parser = argparse.ArgumentParser(
        prog="python -m remora.codegen",
        description="Check or regenerate fingerprinted protocol artifacts.",
    )
    parser.add_argument("command", choices=("check", "write"))
    parser.add_argument("--config", default="codegen.toml", help="path to codegen.toml")
    parser.add_argument("--proto-dir", default="src/remora/proto", help="artifact directory")
    parser.add_argument("--packages-dir", default="packages", help="extras distribution root")
    parser.add_argument("--tshark", default=None, help="path to the tshark binary")
    options = parser.parse_args(argv)

    try:
        config = load_config(Path(options.config))
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    try:
        tshark = find_tshark(options.tshark)
        installed = parse_tshark_version(_tshark_version_output(tshark))
        if installed != config.tshark_version:
            print(
                f"error: installed tshark {installed} does not match the pinned "
                f"{config.tshark_version} in {options.config}; install the pinned version "
                "or update the pin and regenerate every artifact",
                file=sys.stderr,
            )
            return 2
        # The pin is checked first so a mismatched build never pays for the dumps.
        fields_dump, plugins_dump = _tshark_dumps(tshark)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"error: {_environment_error_message(error)}", file=sys.stderr)
        return 2

    try:
        dists, warnings = generate_distributions(config, fields_dump, plugins_dump=plugins_dump)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for warning in warnings:
        if isinstance(warning, ParseWarning):
            print(f"warning: -G fields line {warning.line_no}: {warning.message}", file=sys.stderr)
        else:
            print(f"warning: {warning.abbrev}: {warning.message}", file=sys.stderr)

    proto_dir = Path(options.proto_dir)

    def dest_dir(dest: str) -> Path:
        if dest == "core":
            return proto_dir
        return Path(options.packages_dir) / f"remora-{dest}" / "src" / "remora" / "proto"

    total = sum(len(artifacts) for artifacts in dists.values())
    if options.command == "write":
        for dest, artifacts in dists.items():
            directory = dest_dir(dest)
            directory.mkdir(parents=True, exist_ok=True)
            for artifact in artifacts:
                (directory / artifact.name).write_text(artifact.content, encoding="utf-8")
                print(f"wrote {directory / artifact.name}")
        print(f"wrote {total} artifact(s)")
        return 0

    if not proto_dir.is_dir():
        print(
            f"error: proto dir {str(proto_dir)!r} does not exist; pass --proto-dir "
            "or run from the repository root",
            file=sys.stderr,
        )
        return 2

    messages: list[str] = []
    configured: set[Path] = set()
    for dest, artifacts in dists.items():
        directory = dest_dir(dest)
        configured.add(directory)
        if not directory.is_dir():
            messages.append(f"{directory}: missing (regenerate with the write command)")
            continue
        messages.extend(check_artifacts(artifacts, directory).messages)
    # A distribution dropped from codegen.toml leaves its tree on disk, where
    # nothing above would ever look at it again. Check it against an empty
    # expected set so every fingerprinted file left behind reports as an orphan.
    packages_dir = Path(options.packages_dir)
    if packages_dir.is_dir():
        for stale_dir in sorted(packages_dir.glob("remora-*/src/remora/proto")):
            if not stale_dir.is_dir() or stale_dir in configured:
                continue
            messages.extend(
                f"{stale_dir}: {message}" for message in check_artifacts((), stale_dir).messages
            )
    if messages:
        for message in messages:
            print(message, file=sys.stderr)
        print(
            f"error: {len(messages)} artifact problem(s); regenerate with "
            f"`uv run python -m remora.codegen write` under tshark "
            f"{config.tshark_version}",
            file=sys.stderr,
        )
        return 1
    print(f"codegen artifacts in sync ({total} artifact(s) checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
