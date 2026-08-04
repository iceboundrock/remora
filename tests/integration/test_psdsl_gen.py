"""End-to-end ``psdsl gen`` against a real local tshark (issue #21)."""

from __future__ import annotations

import importlib
import os
import shutil
import sys
from pathlib import Path

import pytest

from remora.codegen.cli import main
from remora.codegen.fingerprint import parse_header

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        shutil.which(os.environ.get("TSHARK") or "tshark") is None
        and not os.environ.get("REMORA_REQUIRE_TSHARK"),
        reason="tshark not installed; skipping integration tests",
    ),
]


def test_gen_udp_produces_importable_fingerprinted_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = tmp_path / "genproto"
    assert main(["gen", "--protocols", "udp", "--out", str(out)]) == 0
    py_source = (out / "udp.py").read_text(encoding="utf-8")
    pyi_source = (out / "udp.pyi").read_text(encoding="utf-8")
    for source in (py_source, pyi_source):
        fingerprint = parse_header(source)
        assert fingerprint is not None
        assert fingerprint.dump_sha256 != ""
    monkeypatch.syspath_prepend(str(tmp_path))
    try:
        module = importlib.import_module("genproto.udp")
        assert "srcport" in module.UDP._table_
    finally:
        sys.modules.pop("genproto.udp", None)
        sys.modules.pop("genproto", None)


def test_gen_unknown_protocol_fails_cleanly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["gen", "--protocols", "remora-no-such-proto", "--out", str(tmp_path / "gen")])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "error:" in captured.err
    assert "remora-no-such-proto" in captured.err
