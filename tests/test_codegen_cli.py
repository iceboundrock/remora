"""Tests for the ``psdsl`` CLI (issue #21). No tshark needed outside integration."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

import remora.codegen.fingerprint as fingerprint_module
from remora.codegen.cli import main
from remora.codegen.fingerprint import parse_header

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

SAMPLE_DUMP = (
    "P\tUser Datagram Protocol\tudp\n"
    "F\tSource Port\tudp.srcport\tFT_UINT16\tudp\tBASE_PT_UDP\t0x0\t\n"
    "F\tStream index\tudp.stream\tFT_UINT32\tudp\tBASE_DEC\t0x0\t\n"
)


@pytest.fixture
def fake_tshark(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        fingerprint_module,
        "_tshark_version_output",
        lambda tshark: "TShark (Wireshark) 4.6.7 (Git).",
    )
    monkeypatch.setattr(fingerprint_module, "_tshark_dumps", lambda tshark: (SAMPLE_DUMP, ""))
    monkeypatch.setenv("TSHARK", "/usr/bin/true")


class TestGen:
    def test_writes_fingerprinted_pair(
        self, tmp_path: Path, fake_tshark: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out = tmp_path / "gen"
        assert main(["gen", "--protocols", "udp", "--out", str(out)]) == 0
        py = (out / "udp.py").read_text(encoding="utf-8")
        pyi = (out / "udp.pyi").read_text(encoding="utf-8")
        for source in (py, pyi):
            fingerprint = parse_header(source)
            assert fingerprint is not None
            assert fingerprint.tshark_version == "4.6.7"
        captured = capsys.readouterr()
        assert "2 artifact(s)" in captured.out

    def test_creates_missing_out_dir_parents(self, tmp_path: Path, fake_tshark: None) -> None:
        out = tmp_path / "a" / "b" / "gen"
        assert main(["gen", "--protocols", "udp", "--out", str(out)]) == 0
        assert (out / "udp.py").is_file()

    def test_duplicate_protocols_deduplicated(
        self, tmp_path: Path, fake_tshark: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out = tmp_path / "gen"
        assert main(["gen", "--protocols", "udp", "udp", "--out", str(out)]) == 0
        assert "2 artifact(s)" in capsys.readouterr().out

    def test_unknown_protocol_exits_2(
        self, tmp_path: Path, fake_tshark: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["gen", "--protocols", "nonsense", "--out", str(tmp_path / "gen")]) == 2
        captured = capsys.readouterr()
        assert "error:" in captured.err
        assert "nonsense" in captured.err
        assert not (tmp_path / "gen").exists()

    def test_missing_tshark_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        missing = str(tmp_path / "nonexistent" / "tshark")
        argv = ["gen", "--protocols", "udp", "--out", str(tmp_path / "gen"), "--tshark", missing]
        assert main(argv) == 2
        captured = capsys.readouterr()
        assert "error:" in captured.err
        assert "tshark not found" in captured.err

    def test_parse_warnings_printed_without_failing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        dump = SAMPLE_DUMP + "X\tbogus record\n"
        monkeypatch.setattr(
            fingerprint_module,
            "_tshark_version_output",
            lambda tshark: "TShark (Wireshark) 4.6.7 (Git).",
        )
        monkeypatch.setattr(fingerprint_module, "_tshark_dumps", lambda tshark: (dump, ""))
        monkeypatch.setenv("TSHARK", "/usr/bin/true")
        assert main(["gen", "--protocols", "udp", "--out", str(tmp_path / "gen")]) == 0
        assert "warning:" in capsys.readouterr().err

    def test_unwritable_out_dir_exits_2(
        self, tmp_path: Path, fake_tshark: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        gen_file = tmp_path / "gen"
        gen_file.write_text("", encoding="utf-8")
        out = gen_file / "sub"
        assert main(["gen", "--protocols", "udp", "--out", str(out)]) == 2
        captured = capsys.readouterr()
        assert "error:" in captured.err

    def test_repeated_protocols_flag_accumulates(
        self, tmp_path: Path, fake_tshark: None, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out = tmp_path / "gen"
        assert main(["gen", "--protocols", "udp", "--protocols", "udp", "--out", str(out)]) == 0
        assert "2 artifact(s)" in capsys.readouterr().out

    def test_repeated_protocols_flag_extends_parser_level(self) -> None:
        from remora.codegen.cli import _build_parser

        options = _build_parser().parse_args(["gen", "--protocols", "udp", "--protocols", "dns"])
        assert options.protocols == ["udp", "dns"]

    def test_multi_flag_emits_multifield(self, tmp_path: Path, fake_tshark: None) -> None:
        out = tmp_path / "gen"
        argv = ["gen", "--protocols", "udp", "--multi", "udp.srcport", "--out", str(out)]
        assert main(argv) == 0
        pyi = (out / "udp.pyi").read_text(encoding="utf-8")
        assert "srcport: MultiField[int]" in pyi
        assert "stream: Field[int]" in pyi  # unlisted field stays scalar
        py = (out / "udp.py").read_text(encoding="utf-8")
        assert '"srcport": ("udp.srcport", "FT_UINT16", 1)' in py
        assert '"stream": ("udp.stream", "FT_UINT32", 0)' in py

    def test_multi_defaults_to_all_scalar(self, tmp_path: Path, fake_tshark: None) -> None:
        out = tmp_path / "gen"
        assert main(["gen", "--protocols", "udp", "--out", str(out)]) == 0
        pyi = (out / "udp.pyi").read_text(encoding="utf-8")
        assert "MultiField" not in pyi

    def test_repeated_multi_flag_extends_parser_level(self) -> None:
        from remora.codegen.cli import _build_parser

        options = _build_parser().parse_args(
            ["gen", "--protocols", "udp", "--multi", "udp.srcport", "--multi", "udp.stream"]
        )
        assert options.multi == ["udp.srcport", "udp.stream"]


class TestHelp:
    def test_gen_help_documents_every_flag(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["gen", "--help"])
        assert excinfo.value.code == 0
        message = capsys.readouterr().out
        for flag in ("--tshark", "--protocols", "--out", "--multi"):
            assert flag in message

    def test_top_level_help_lists_gen(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as excinfo:
            main(["--help"])
        assert excinfo.value.code == 0
        assert "gen" in capsys.readouterr().out


def test_pyproject_declares_psdsl_console_script() -> None:
    """The psdsl entry point must target cli.main (issue #21)."""
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    with pyproject.open("rb") as handle:
        data = tomllib.load(handle)
    assert data["project"]["scripts"]["psdsl"] == "remora.codegen.cli:main"


class TestGeneratedOutputImport:
    def test_import_from_temp_out_dir(
        self, tmp_path: Path, fake_tshark: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The documented mechanism: out dir = package dir, parent on sys.path."""
        out = tmp_path / "genproto"
        assert main(["gen", "--protocols", "udp", "--out", str(out)]) == 0
        monkeypatch.syspath_prepend(str(tmp_path))
        try:
            module = importlib.import_module("genproto.udp")
            udp = module.UDP
            ref = udp.srcport == 53
            assert type(ref).__name__ == "Comparison"
            assert udp._table_["srcport"] == ("udp.srcport", "FT_UINT16", 0)
            assert (out / "udp.pyi").is_file()  # stub sits beside the module
        finally:
            sys.modules.pop("genproto.udp", None)
            sys.modules.pop("genproto", None)
