"""Tests for the fingerprint header + drift check (issue #16). No tshark needed."""

from __future__ import annotations

from pathlib import Path

import pytest

from remora.codegen.fingerprint import (
    Artifact,
    CheckReport,
    CodegenConfig,
    Fingerprint,
    add_header,
    check_artifacts,
    generate_artifacts,
    load_config,
    make_fingerprint,
    parse_header,
    render_header,
    summarize_env,
)

SAMPLE_DUMP = (
    "P\tUser Datagram Protocol\tudp\n"
    "F\tSource Port\tudp.srcport\tFT_UINT16\tudp\tBASE_PT_UDP\t0x0\t\n"
    "F\tStream index\tudp.stream\tFT_UINT32\tudp\tBASE_DEC\t0x0\t\n"
)


def fp(**overrides: str) -> Fingerprint:
    base: dict[str, str] = {
        "tshark_version": "4.6.6",
        "dump_sha256": "ab" * 32,
        "env": "plugins=none",
        "generator": "remora 0.1.0",
    }
    base.update(overrides)
    return Fingerprint(**base)


class TestFingerprintValue:
    def test_make_fingerprint_hashes_dump(self) -> None:
        import hashlib

        result = make_fingerprint(SAMPLE_DUMP, tshark_version="4.6.6")
        assert result.tshark_version == "4.6.6"
        assert result.dump_sha256 == hashlib.sha256(SAMPLE_DUMP.encode()).hexdigest()
        assert result.env == "plugins=none"
        assert result.generator.startswith("remora ")

    def test_changes_when_dump_changes(self) -> None:
        a = make_fingerprint(SAMPLE_DUMP, tshark_version="4.6.6")
        b = make_fingerprint(SAMPLE_DUMP + "X", tshark_version="4.6.6")
        assert a != b
        assert render_header(a) != render_header(b)

    def test_changes_when_tshark_version_changes(self) -> None:
        a = make_fingerprint(SAMPLE_DUMP, tshark_version="4.6.6")
        b = make_fingerprint(SAMPLE_DUMP, tshark_version="4.6.7")
        assert a != b
        assert render_header(a) != render_header(b)

    def test_env_summary(self) -> None:
        assert summarize_env("") == "plugins=none"
        assert summarize_env("   \n") == "plugins=none"
        hashed = summarize_env("mate 1.0 codec\n")
        assert hashed.startswith("plugins=sha256:")
        assert len(hashed) == len("plugins=sha256:") + 12
        assert summarize_env("other\n") != hashed


class TestHeader:
    def test_render_shape(self) -> None:
        header = render_header(fp())
        lines = header.splitlines()
        assert lines[0] == "# remora-fingerprint: v1"
        assert lines[1] == "# tshark: 4.6.6"
        assert lines[2] == f"# dump-sha256: {'ab' * 32}"
        assert lines[3] == "# env: plugins=none"
        assert lines[4] == "# generator: remora 0.1.0"
        assert header.endswith("\n")
        assert all(len(line) <= 100 for line in lines)

    def test_parse_round_trip(self) -> None:
        original = fp()
        source = add_header('"""Doc."""\n\nX = 1\n', original)
        assert parse_header(source) == original

    def test_add_header_keeps_source_and_blank_line(self) -> None:
        source = add_header('"""Doc."""\n\nX = 1\n', fp())
        assert source.endswith('"""Doc."""\n\nX = 1\n')
        lines = source.splitlines()
        assert lines[5] == ""
        assert lines[6] == '"""Doc."""'

    def test_parse_header_absent(self) -> None:
        assert parse_header('"""A seed module without a header."""\n') is None
        assert parse_header("") is None

    def test_parse_header_malformed(self) -> None:
        broken = "# remora-fingerprint: v1\n# tshark: 4.6.6\n"
        assert parse_header(broken) is None


class TestLoadConfig:
    def test_load(self, tmp_path: Path) -> None:
        config_file = tmp_path / "codegen.toml"
        config_file.write_text(
            '[tshark]\nversion = "4.6.6"\n\n'
            '[generate]\nprotocols = ["udp", "dns"]\nmulti = ["dns.qry.name"]\n',
            encoding="utf-8",
        )
        config = load_config(config_file)
        assert config == CodegenConfig(
            tshark_version="4.6.6", protocols=("udp", "dns"), multi=frozenset({"dns.qry.name"})
        )

    def test_missing_version_rejected(self, tmp_path: Path) -> None:
        config_file = tmp_path / "codegen.toml"
        config_file.write_text("[generate]\nprotocols = []\nmulti = []\n", encoding="utf-8")
        with pytest.raises(ValueError, match=r"\[tshark\] version"):
            load_config(config_file)

    def test_wrong_type_rejected(self, tmp_path: Path) -> None:
        config_file = tmp_path / "codegen.toml"
        config_file.write_text(
            '[tshark]\nversion = "4.6.6"\n[generate]\nprotocols = "udp"\nmulti = []\n',
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="protocols"):
            load_config(config_file)

    def test_repo_config_is_loadable_and_empty(self) -> None:
        config = load_config(Path(__file__).parent.parent / "codegen.toml")
        assert config.tshark_version
        assert config.protocols == ()
        assert config.multi == frozenset()


def _config(**overrides: object) -> CodegenConfig:
    base: dict[str, object] = {
        "tshark_version": "4.6.6",
        "protocols": ("udp",),
        "multi": frozenset(),
    }
    base.update(overrides)
    return CodegenConfig(**base)  # type: ignore[arg-type]


class TestGenerateArtifacts:
    def test_generates_headered_pair_per_protocol(self) -> None:
        artifacts, warnings = generate_artifacts(_config(), SAMPLE_DUMP)
        assert warnings == ()
        assert [a.name for a in artifacts] == ["udp.py", "udp.pyi"]
        for artifact in artifacts:
            header = parse_header(artifact.content)
            assert header is not None
            assert header.tshark_version == "4.6.6"
        py = artifacts[0].content
        assert '"srcport": ("udp.srcport", "FT_UINT16", 0),' in py
        assert '"stream": ("udp.stream", "FT_UINT32", 0),' in py

    def test_multi_flag_flows_through(self) -> None:
        artifacts, _ = generate_artifacts(_config(multi=frozenset({"udp.stream"})), SAMPLE_DUMP)
        assert '"stream": ("udp.stream", "FT_UINT32", 1),' in artifacts[0].content
        assert "stream: MultiField[int]" in artifacts[1].content

    def test_unknown_protocol_raises(self) -> None:
        with pytest.raises(ValueError, match="nope"):
            generate_artifacts(_config(protocols=("nope",)), SAMPLE_DUMP)

    def test_empty_config_generates_nothing(self) -> None:
        artifacts, warnings = generate_artifacts(_config(protocols=()), SAMPLE_DUMP)
        assert artifacts == ()
        assert warnings == ()

    def test_deterministic(self) -> None:
        assert generate_artifacts(_config(), SAMPLE_DUMP) == generate_artifacts(
            _config(), SAMPLE_DUMP
        )


class TestCheckArtifacts:
    def _write_all(self, proto_dir: Path, artifacts: tuple[Artifact, ...]) -> None:
        proto_dir.mkdir(exist_ok=True)
        for artifact in artifacts:
            (proto_dir / artifact.name).write_text(artifact.content, encoding="utf-8")

    def test_in_sync(self, tmp_path: Path) -> None:
        artifacts, _ = generate_artifacts(_config(), SAMPLE_DUMP)
        self._write_all(tmp_path, artifacts)
        report = check_artifacts(artifacts, tmp_path)
        assert report == CheckReport(ok=True, messages=())

    def test_drift_produces_readable_diff(self, tmp_path: Path) -> None:
        artifacts, _ = generate_artifacts(_config(), SAMPLE_DUMP)
        self._write_all(tmp_path, artifacts)
        stale = (
            (tmp_path / "udp.py").read_text(encoding="utf-8").replace('"FT_UINT16"', '"FT_UINT32"')
        )
        (tmp_path / "udp.py").write_text(stale, encoding="utf-8")
        report = check_artifacts(artifacts, tmp_path)
        assert not report.ok
        joined = "\n".join(report.messages)
        assert "udp.py" in joined
        assert "-" in joined and "+" in joined
        assert "FT_UINT16" in joined and "FT_UINT32" in joined

    def test_missing_file_reported(self, tmp_path: Path) -> None:
        artifacts, _ = generate_artifacts(_config(), SAMPLE_DUMP)
        self._write_all(tmp_path, artifacts)
        (tmp_path / "udp.pyi").unlink()
        report = check_artifacts(artifacts, tmp_path)
        assert not report.ok
        assert any("udp.pyi" in m and "missing" in m for m in report.messages)

    def test_orphan_fingerprinted_file_reported(self, tmp_path: Path) -> None:
        artifacts, _ = generate_artifacts(_config(), SAMPLE_DUMP)
        self._write_all(tmp_path, artifacts)
        orphan = add_header('"""Stale."""\n', fp())
        (tmp_path / "old.py").write_text(orphan, encoding="utf-8")
        report = check_artifacts(artifacts, tmp_path)
        assert not report.ok
        assert any("old.py" in m and "orphan" in m for m in report.messages)

    def test_headerless_seed_files_ignored(self, tmp_path: Path) -> None:
        artifacts, _ = generate_artifacts(_config(), SAMPLE_DUMP)
        self._write_all(tmp_path, artifacts)
        (tmp_path / "eth.py").write_text('"""Seed, no header."""\n', encoding="utf-8")
        (tmp_path / "__init__.py").write_text("", encoding="utf-8")
        report = check_artifacts(artifacts, tmp_path)
        assert report.ok
