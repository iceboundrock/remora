"""The ``psdsl`` console script: local generation against the user's tshark.

Published packages can only cover protocols a stock tshark knows. Users with
plugins, Lua dissectors, or unusual protocols regenerate locally instead:
``psdsl gen`` runs the same dump → parse → emit → fingerprint pipeline as
``python -m remora.codegen write``, but against whatever tshark is installed
(no version pin, no ``codegen.toml``) and into a directory of the user's
choosing. The output directory is a plain package directory — each ``.pyi``
sits beside its ``.py``, so IDEs resolve stubs as soon as the parent directory
is on the import path (see README "Local generation").

All subprocess access goes through the seams in
:mod:`remora.codegen.fingerprint` (``_tshark_version_output``,
``_tshark_dumps``) so tests drive this CLI without a tshark binary.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from remora.codegen import fingerprint
from remora.codegen.fingerprint import (
    CodegenConfig,
    find_tshark,
    generate_artifacts,
    parse_tshark_version,
)
from remora.codegen.parse import ParseWarning


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="psdsl",
        description="Remora code generation against the locally installed tshark.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    gen = subparsers.add_parser(
        "gen",
        help="generate protocol modules from the local tshark",
        description=(
            "Run the dump → parse → emit → fingerprint pipeline against the local "
            "tshark and write importable .py/.pyi pairs to the output directory. Every "
            "generated field is scalar—multi-occurrence fields resolve to their first "
            "occurrence."
        ),
    )
    gen.add_argument(
        "--tshark",
        default=None,
        metavar="PATH",
        help="path to the tshark binary (default: $TSHARK, then PATH, then Homebrew)",
    )
    gen.add_argument(
        "--protocols",
        nargs="+",
        action="extend",
        required=True,
        metavar="NAME",
        help="tshark protocol abbrevs to generate (e.g. udp dns)",
    )
    gen.add_argument(
        "--out",
        default="gen",
        metavar="DIR",
        help="output directory, created if missing (default: ./gen)",
    )
    return parser


def _cmd_gen(options: argparse.Namespace) -> int:
    try:
        tshark = find_tshark(options.tshark)
        version = parse_tshark_version(fingerprint._tshark_version_output(tshark))
        fields_dump, plugins_dump = fingerprint._tshark_dumps(tshark)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"error: {fingerprint._environment_error_message(error)}", file=sys.stderr)
        return 2

    config = CodegenConfig(
        tshark_version=version,
        protocols=tuple(dict.fromkeys(options.protocols)),
        multi=frozenset(),
    )
    try:
        artifacts, warnings = generate_artifacts(config, fields_dump, plugins_dump=plugins_dump)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    for warning in warnings:
        if isinstance(warning, ParseWarning):
            print(f"warning: -G fields line {warning.line_no}: {warning.message}", file=sys.stderr)
        else:
            print(f"warning: {warning.abbrev}: {warning.message}", file=sys.stderr)

    out_dir = Path(options.out)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        for artifact in artifacts:
            (out_dir / artifact.name).write_text(artifact.content, encoding="utf-8")
            print(f"wrote {out_dir / artifact.name}")
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(f"wrote {len(artifacts)} artifact(s) under tshark {version}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``psdsl`` console script."""
    options = _build_parser().parse_args(argv)
    assert options.command == "gen"  # the only subcommand so far
    return _cmd_gen(options)


if __name__ == "__main__":
    raise SystemExit(main())
