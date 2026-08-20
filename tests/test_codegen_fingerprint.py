"""Tests for the fingerprint header + drift check (issue #16). No tshark needed."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

import remora.codegen.fingerprint as fingerprint_module
from remora.codegen.emit import EmitWarning
from remora.codegen.fingerprint import (
    Artifact,
    CheckReport,
    CodegenConfig,
    Fingerprint,
    add_header,
    canonicalize_dump,
    check_artifacts,
    generate_artifacts,
    generate_distributions,
    load_config,
    main,
    make_fingerprint,
    parse_header,
    parse_tshark_version,
    render_header,
    summarize_env,
)
from remora.codegen.parse import ParseWarning

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

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


def plugins_dump(triplet: str, *, mate_version: str = "1.0.1") -> str:
    """A realistic ``-G plugins`` dump for one multiarch triplet (name/version/type/path)."""
    lib = f"/usr/lib/{triplet}/wireshark/plugins/4.6"
    return (
        f"g711.so         \t0.1.0\tcodec\t{lib}/codecs/g711.so\n"
        f"mate.so         \t{mate_version}\tdissector\t{lib}/epan/mate.so\n"
        f"usbdump.so      \t0.0.1\tfile type\t{lib}/wiretap/usbdump.so\n"
    )


class TestSummarizeEnvIsArchitectureIndependent:
    """``env:`` hashes (name, version, type) only — never the arch-shaped path (#97)."""

    def test_multiarch_paths_do_not_change_the_summary(self) -> None:
        amd64 = plugins_dump("x86_64-linux-gnu")
        arm64 = plugins_dump("aarch64-linux-gnu")
        assert amd64 != arm64
        assert summarize_env(amd64) == summarize_env(arm64)

    def test_a_version_change_does_change_the_summary(self) -> None:
        assert summarize_env(plugins_dump("x86_64-linux-gnu")) != summarize_env(
            plugins_dump("x86_64-linux-gnu", mate_version="1.0.2")
        )

    def test_a_name_or_type_change_does_change_the_summary(self) -> None:
        base = "a\t1.0\tcodec\t/usr/lib/x/a.so\n"
        assert summarize_env(base) != summarize_env("b\t1.0\tcodec\t/usr/lib/x/a.so\n")
        assert summarize_env(base) != summarize_env("a\t1.0\tdissector\t/usr/lib/x/a.so\n")

    def test_fields_stay_tab_separated_so_they_cannot_collide(self) -> None:
        assert summarize_env("a\tb.c\tcodec\t/p\n") != summarize_env("a.b\tc\tcodec\t/p\n")

    def test_dropping_the_path_column_is_all_that_changes(self) -> None:
        """A dump already free of a path column hashes like the full one."""
        assert summarize_env(plugins_dump("x86_64-linux-gnu")) == summarize_env(
            "g711.so         \t0.1.0\tcodec\t\n"
            "mate.so         \t1.0.1\tdissector\t\n"
            "usbdump.so      \t0.0.1\tfile type\t\n"
        )

    def test_malformed_lines_are_kept_whole_and_distinguished(self) -> None:
        """Hashing stays total: a line without four columns is kept, not dropped."""
        assert summarize_env("a\t1.0\tcodec\n") != summarize_env("a\t1.0\tdissector\n")
        assert summarize_env("not a record at all\n") != summarize_env("plugins\n")
        assert summarize_env("a\t1.0\n") != summarize_env("a\t1.0\tcodec\t/p\n")

    def test_a_malformed_record_never_collides_with_a_reduced_valid_one(self) -> None:
        """The exact collision the marker exists for: three columns vs four-minus-path.

        ``a\\t1.0\\tcodec`` is malformed; ``a\\t1.0\\tcodec\\t/path`` is valid and
        reduces to the same three columns. Marking the malformed line keeps the
        two apart — a NUL can never appear in a record tshark printed, so the
        marked and unmarked spaces are disjoint.
        """
        assert summarize_env("a\t1.0\tcodec\n") != summarize_env("a\t1.0\tcodec\t/path\n")
        # ...and the malformed line is still not confusable with any other path.
        assert summarize_env("a\t1.0\tcodec\n") != summarize_env("a\t1.0\tcodec\t/other\n")

    def test_an_extra_column_record_never_collides_with_a_valid_one(self) -> None:
        """Well-formed is *exactly* four columns, so truncation cannot forge one.

        Treating four as a minimum let a five-column line be reduced to its
        first three columns and hash like the valid four-column record sharing
        that ``(name, version, type)``. Five columns is malformed, so it is
        marked and kept whole instead.
        """
        five = "a\t1.0\tcodec\t/path\textra\n"
        assert summarize_env(five) != summarize_env("a\t1.0\tcodec\t/path\n")
        # Extra columns still carry information, so two of them stay distinct.
        assert summarize_env(five) != summarize_env("a\t1.0\tcodec\t/path\tother\n")
        # And a six-column line is neither of them.
        assert summarize_env(five) != summarize_env("a\t1.0\tcodec\t/path\textra\tmore\n")

    def test_the_marker_leaves_well_formed_dumps_untouched(self) -> None:
        """Only malformed lines are marked, so committed ``env:`` values are stable.

        States the hashed text independently: three tab-separated columns per
        record, newline-terminated, no marker anywhere.
        """
        import hashlib

        material = (
            "g711.so         \t0.1.0\tcodec\n"
            "mate.so         \t1.0.1\tdissector\n"
            "usbdump.so      \t0.0.1\tfile type\n"
        )
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
        assert summarize_env(plugins_dump("x86_64-linux-gnu")) == f"plugins=sha256:{digest}"
        assert digest == "bd876b138bf2"

    def test_blank_lines_are_ignored(self) -> None:
        dump = plugins_dump("x86_64-linux-gnu")
        assert summarize_env(dump) == summarize_env(f"\n{dump}   \n\n")

    def test_record_order_is_preserved(self) -> None:
        """``-G plugins`` emission order is stable, so it is hashed as emitted."""
        forward = "a\t1.0\tcodec\t/p\nb\t1.0\tcodec\t/p\n"
        reversed_ = "b\t1.0\tcodec\t/p\na\t1.0\tcodec\t/p\n"
        assert summarize_env(forward) != summarize_env(reversed_)

    def test_digest_is_stable(self) -> None:
        """Golden: the ``env:`` value of every committed artifact depends on it."""
        assert summarize_env(plugins_dump("x86_64-linux-gnu")) == "plugins=sha256:bd876b138bf2"


REPO_ROOT = Path(__file__).resolve().parents[1]


def load_arch_probe() -> ModuleType:
    """Load the CI arch probe by path (``.github/scripts`` is not a package)."""
    path = REPO_ROOT / ".github" / "scripts" / "codegen_arch_probe.py"
    spec = importlib.util.spec_from_file_location("codegen_arch_probe", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestArchProbePinGate:
    """The arch probe must refuse to record evidence for an unpinned tshark (#97)."""

    def test_matching_version_passes_the_gate(self) -> None:
        probe = load_arch_probe()
        assert probe.pin_mismatch_message("4.6.6", "4.6.6", "codegen.toml") is None

    def test_mismatched_version_is_refused_naming_both(self) -> None:
        probe = load_arch_probe()
        message = probe.pin_mismatch_message("4.6.7", "4.6.6", "codegen.toml")
        assert message is not None
        assert "4.6.7" in message
        assert "4.6.6" in message
        assert "codegen.toml" in message

    def test_the_pin_is_read_from_the_repository_config(self) -> None:
        """The probe never restates a version: it reads ``codegen.toml``."""
        probe = load_arch_probe()
        assert probe.CONFIG_PATH == REPO_ROOT / "codegen.toml"
        source = probe.CONFIG_PATH.read_text(encoding="utf-8")
        pinned = load_config(probe.CONFIG_PATH).tshark_version
        assert pinned in source
        probe_source = (REPO_ROOT / ".github" / "scripts" / "codegen_arch_probe.py").read_text(
            encoding="utf-8"
        )
        assert pinned not in probe_source


class TestCanonicalizeDump:
    """tshark shuffles ``-G fields`` between runs; canonicalizing pins it (#68)."""

    def test_sorts_lines(self) -> None:
        assert canonicalize_dump("c\na\nb\n") == "a\nb\nc\n"

    def test_drops_empty_lines(self) -> None:
        assert canonicalize_dump("b\n\n   \na\n") == "a\nb\n"

    def test_is_idempotent(self) -> None:
        once = canonicalize_dump(SAMPLE_DUMP)
        assert canonicalize_dump(once) == once

    def test_shuffled_dumps_canonicalize_identically(self) -> None:
        lines = SAMPLE_DUMP.splitlines(keepends=True)
        shuffled = "".join(reversed(lines))
        assert shuffled != SAMPLE_DUMP
        assert canonicalize_dump(shuffled) == canonicalize_dump(SAMPLE_DUMP)

    def test_preserves_the_record_set(self) -> None:
        assert set(canonicalize_dump(SAMPLE_DUMP).splitlines()) == set(SAMPLE_DUMP.splitlines())

    def test_empty_dump_stays_empty(self) -> None:
        assert canonicalize_dump("") == ""
        assert canonicalize_dump("\n  \n") == ""


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

    def test_non_table_tshark_section_rejected(self, tmp_path: Path) -> None:
        config_file = tmp_path / "codegen.toml"
        config_file.write_text("tshark = 5\n", encoding="utf-8")
        with pytest.raises(ValueError, match=r"\[tshark\] must be a table"):
            load_config(config_file)

    def test_non_table_generate_section_rejected(self, tmp_path: Path) -> None:
        config_file = tmp_path / "codegen.toml"
        config_file.write_text('generate = 5\n\n[tshark]\nversion = "4.6.6"\n', encoding="utf-8")
        with pytest.raises(ValueError, match=r"\[generate\] must be a table"):
            load_config(config_file)

    def test_repo_config_is_loadable_and_pinned(self) -> None:
        config = load_config(Path(__file__).parent.parent / "codegen.toml")
        assert config.tshark_version
        # Issue #19 core protocol set: 30 protocols, 22 multi fields
        # (the M1 seed multi set + ipv6.addr + sctp.port).
        assert len(config.protocols) == 30
        assert len(config.multi) == 22
        # Spot-check multi membership
        assert {"ipv6.addr", "sctp.port", "tcp.port", "dns.qry.name"} <= config.multi
        # Spot-check protocol membership
        assert "tls" in config.protocols

    def test_extras_parsed_in_order(self, tmp_path: Path) -> None:
        path = tmp_path / "codegen.toml"
        path.write_text(
            "[tshark]\nversion = '4.6.6'\n"
            "[generate]\nprotocols = ['udp']\n"
            "[extras.wireless]\nprotocols = ['wlan', 'radiotap']\n"
            "[extras.telecom]\nprotocols = ['gtp']\n",
            encoding="utf-8",
        )
        config = load_config(path)
        assert config.extras == (
            ("wireless", ("wlan", "radiotap")),
            ("telecom", ("gtp",)),
        )

    def test_extras_default_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "codegen.toml"
        path.write_text("[tshark]\nversion = '4.6.6'\n", encoding="utf-8")
        assert load_config(path).extras == ()

    def test_extras_non_table_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "codegen.toml"
        path.write_text(
            "[tshark]\nversion = '4.6.6'\n[extras]\nwireless = ['wlan']\n",
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match=r"\[extras\.wireless\] must be a table"):
            load_config(path)

    def test_extra_named_core_rejected(self, tmp_path: Path) -> None:
        """``core`` is the reserved destination name; it must not be an extra."""
        path = tmp_path / "codegen.toml"
        path.write_text(
            "[tshark]\nversion = '4.6.6'\n"
            "[generate]\nprotocols = ['udp']\n"
            "[extras.core]\nprotocols = ['wlan']\n",
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match=r"unknown extra 'core'"):
            load_config(path)

    def test_unknown_extra_name_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "codegen.toml"
        path.write_text(
            "[tshark]\nversion = '4.6.6'\n[extras.bogus]\nprotocols = ['wlan']\n",
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match=r"unknown extra 'bogus'; allowed: "):
            load_config(path)

    def test_protocol_in_core_and_extra_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "codegen.toml"
        path.write_text(
            "[tshark]\nversion = '4.6.6'\n"
            "[generate]\nprotocols = ['wlan']\n"
            "[extras.wireless]\nprotocols = ['wlan']\n",
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="'wlan' assigned more than once"):
            load_config(path)

    def test_protocol_in_two_extras_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "codegen.toml"
        path.write_text(
            "[tshark]\nversion = '4.6.6'\n"
            "[extras.wireless]\nprotocols = ['wlan']\n"
            "[extras.industrial]\nprotocols = ['wlan']\n",
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="'wlan' assigned more than once"):
            load_config(path)


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

    def test_duplicate_protocol_in_config_raises(self) -> None:
        with pytest.raises(ValueError, match=r"module name.*collides"):
            generate_artifacts(_config(protocols=("udp", "udp")), SAMPLE_DUMP)

    def test_parse_warnings_are_surfaced(self) -> None:
        dump = SAMPLE_DUMP + "P\tUser Datagram Protocol\tudp\nZ\tnot a record type\n"
        artifacts, warnings = generate_artifacts(_config(), dump)
        assert [a.name for a in artifacts] == ["udp.py", "udp.pyi"]
        assert all(isinstance(w, ParseWarning) for w in warnings)
        assert [(w.line_no, w.message) for w in warnings if isinstance(w, ParseWarning)] == [
            (4, "duplicate protocol abbrev 'udp'"),
            (5, "unknown record type 'Z'"),
        ]

    def test_parse_warnings_come_before_emit_warnings(self) -> None:
        dump = (
            SAMPLE_DUMP
            + "Z\tnot a record type\n"
            + "F\tA B\tudp.a.b\tFT_UINT16\tudp\tBASE_DEC\t0x0\t\n"
            + "F\tA-B\tudp.a-b\tFT_UINT16\tudp\tBASE_DEC\t0x0\t\n"
        )
        _, warnings = generate_artifacts(_config(), dump)
        assert [type(w) for w in warnings] == [ParseWarning, EmitWarning]
        first, second = warnings
        assert isinstance(first, ParseWarning)
        assert first.line_no == 4
        assert isinstance(second, EmitWarning)
        assert second.abbrev == "udp.a-b"

    def test_colliding_module_names_raise(self) -> None:
        # Create a dump with two protocols that mangle to the same name:
        # 'x.y' and 'x-y' both mangle to 'x_y'
        colliding_dump = (
            "P\tProtocol One\tx.y\n"
            "F\tField A\tx.y.a\tFT_UINT16\tx.y\tBASE_DEC\t0x0\t\n"
            "P\tProtocol Two\tx-y\n"
            "F\tField B\tx-y.b\tFT_UINT16\tx-y\tBASE_DEC\t0x0\t\n"
        )
        with pytest.raises(ValueError, match=r"module name.*collides"):
            generate_artifacts(_config(protocols=("x.y", "x-y")), colliding_dump)


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


class TestParseTsharkVersion:
    def test_release_line(self) -> None:
        line = "TShark (Wireshark) 4.6.6 (Git commit b439fb7b47a9)."
        assert parse_tshark_version(line) == "4.6.6"

    def test_distro_line(self) -> None:
        line = "TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1.1build3).\nmore"
        assert parse_tshark_version(line) == "4.2.2"

    def test_garbage_raises(self) -> None:
        with pytest.raises(ValueError, match="version"):
            parse_tshark_version("not tshark output")


class TestMain:
    def _prepare(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        *,
        reported_version: str = "4.6.6",
        dump: str = SAMPLE_DUMP,
    ) -> tuple[Path, Path]:
        config_file = tmp_path / "codegen.toml"
        config_file.write_text(
            '[tshark]\nversion = "4.6.6"\n[generate]\nprotocols = ["udp"]\nmulti = []\n',
            encoding="utf-8",
        )
        proto_dir = tmp_path / "proto"
        proto_dir.mkdir()
        monkeypatch.setattr(
            fingerprint_module,
            "_tshark_version_output",
            lambda tshark: f"TShark (Wireshark) {reported_version} (Git).",
        )
        monkeypatch.setattr(
            fingerprint_module,
            "_tshark_dumps",
            lambda tshark: (dump, ""),
        )
        monkeypatch.setenv("TSHARK", "/usr/bin/true")
        return config_file, proto_dir

    def _argv(self, command: str, config_file: Path, proto_dir: Path) -> list[str]:
        # --packages-dir is pinned inside tmp_path so the stale-distribution scan
        # cannot wander into the real repo's packages/ tree.
        return [
            command,
            "--config",
            str(config_file),
            "--proto-dir",
            str(proto_dir),
            "--packages-dir",
            str(config_file.parent / "packages"),
        ]

    def test_write_then_check_in_sync(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_file, proto_dir = self._prepare(tmp_path, monkeypatch)
        assert main(self._argv("write", config_file, proto_dir)) == 0
        assert (proto_dir / "udp.py").is_file()
        assert (proto_dir / "udp.pyi").is_file()
        assert (proto_dir / "_extras.py").is_file()  # core always ships the extras map
        capsys.readouterr()  # drain the write output so the check assertions cannot alias it
        assert main(self._argv("check", config_file, proto_dir)) == 0
        checked = capsys.readouterr().out
        assert "in sync" in checked
        assert "3 artifact(s)" in checked

    def test_check_reports_drift(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_file, proto_dir = self._prepare(tmp_path, monkeypatch)
        assert main(self._argv("write", config_file, proto_dir)) == 0
        stale = (proto_dir / "udp.py").read_text(encoding="utf-8") + "# stale\n"
        (proto_dir / "udp.py").write_text(stale, encoding="utf-8")
        assert main(self._argv("check", config_file, proto_dir)) == 1
        captured = capsys.readouterr()
        assert "udp.py" in captured.err
        assert "# stale" in captured.err

    def test_version_mismatch_exits_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_file, proto_dir = self._prepare(tmp_path, monkeypatch, reported_version="4.6.7")
        assert main(self._argv("check", config_file, proto_dir)) == 2
        captured = capsys.readouterr()
        assert "4.6.7" in captured.err
        assert "4.6.6" in captured.err

    def test_version_mismatch_skips_the_expensive_dumps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The pin is compared before ``-G fields``/``-G plugins`` are collected."""
        config_file, proto_dir = self._prepare(tmp_path, monkeypatch, reported_version="4.6.7")

        def explode(tshark: str) -> tuple[str, str]:
            raise AssertionError("dumps must not be collected on pin mismatch")

        monkeypatch.setattr(fingerprint_module, "_tshark_dumps", explode)
        assert main(self._argv("check", config_file, proto_dir)) == 2
        assert "4.6.7" in capsys.readouterr().err

    def test_empty_config_generates_only_the_extras_map(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No protocols still means one artifact: core's ``_extras.py`` is unconditional."""
        config_file, proto_dir = self._prepare(tmp_path, monkeypatch)
        config_file.write_text(
            '[tshark]\nversion = "4.6.6"\n[generate]\nprotocols = []\nmulti = []\n',
            encoding="utf-8",
        )
        assert main(self._argv("check", config_file, proto_dir)) == 1
        assert "_extras.py: missing" in capsys.readouterr().err
        assert main(self._argv("write", config_file, proto_dir)) == 0
        assert [path.name for path in sorted(proto_dir.iterdir())] == ["_extras.py"]
        capsys.readouterr()
        assert main(self._argv("check", config_file, proto_dir)) == 0
        assert "1 artifact(s)" in capsys.readouterr().out

    def test_missing_tshark_exits_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_file, proto_dir = self._prepare(tmp_path, monkeypatch)
        missing = str(tmp_path / "nonexistent" / "tshark")
        argv = [*self._argv("check", config_file, proto_dir), "--tshark", missing]
        assert main(argv) == 2
        captured = capsys.readouterr()
        assert "error:" in captured.err
        assert "tshark not found" in captured.err
        assert missing in captured.err

    def test_failing_tshark_exits_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_file, proto_dir = self._prepare(tmp_path, monkeypatch)

        def explode(tshark: str) -> tuple[str, str]:
            raise subprocess.CalledProcessError(
                2, [tshark, "-G", "fields"], output="", stderr="tshark: bad dissector\n"
            )

        monkeypatch.setattr(fingerprint_module, "_tshark_dumps", explode)
        assert main(self._argv("check", config_file, proto_dir)) == 2
        captured = capsys.readouterr()
        assert "error:" in captured.err
        assert "-G fields" in captured.err
        assert "bad dissector" in captured.err

    def test_unparsable_version_exits_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_file, proto_dir = self._prepare(tmp_path, monkeypatch)
        monkeypatch.setattr(
            fingerprint_module,
            "_tshark_version_output",
            lambda tshark: "not tshark output at all\n",
        )
        assert main(self._argv("check", config_file, proto_dir)) == 2
        captured = capsys.readouterr()
        assert "error:" in captured.err
        assert "version" in captured.err

    def test_check_missing_proto_dir_exits_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_file, proto_dir = self._prepare(tmp_path, monkeypatch)
        missing = proto_dir / "typo"
        assert main(self._argv("check", config_file, missing)) == 2
        captured = capsys.readouterr()
        assert "error:" in captured.err
        assert str(missing) in captured.err

    def test_warnings_printed_to_stderr_without_failing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        dump = (
            SAMPLE_DUMP
            + "Z\tnot a record type\n"
            + "F\tA B\tudp.a.b\tFT_UINT16\tudp\tBASE_DEC\t0x0\t\n"
            + "F\tA-B\tudp.a-b\tFT_UINT16\tudp\tBASE_DEC\t0x0\t\n"
        )
        config_file, proto_dir = self._prepare(tmp_path, monkeypatch, dump=dump)
        assert main(self._argv("write", config_file, proto_dir)) == 0
        captured = capsys.readouterr()
        assert "warning: -G fields line 4: unknown record type 'Z'" in captured.err
        assert "warning: udp.a-b: attribute name 'a_b' already taken" in captured.err

    def test_write_creates_missing_proto_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_file, proto_dir = self._prepare(tmp_path, monkeypatch)
        fresh = proto_dir / "nested" / "generated"
        argv = [
            "write",
            "--config",
            str(config_file),
            "--proto-dir",
            str(fresh),
        ]
        assert main(argv) == 0
        assert (fresh / "udp.py").is_file()
        assert (fresh / "udp.pyi").is_file()
        capsys.readouterr()


class TestSeamCanonicalizesTheFieldsDump:
    """End-to-end proof of the #68 fix: dump order cannot reach the artifacts.

    These patch ``_run_tshark`` rather than ``_tshark_dumps`` so the real seam —
    the one that canonicalizes — actually runs.
    """

    # Same three records as SAMPLE_DUMP, emitted in a different order, as tshark
    # is free to do between two runs of one binary.
    SHUFFLED_DUMP = (
        "F\tStream index\tudp.stream\tFT_UINT32\tudp\tBASE_DEC\t0x0\t\n"
        "F\tSource Port\tudp.srcport\tFT_UINT16\tudp\tBASE_PT_UDP\t0x0\t\n"
        "P\tUser Datagram Protocol\tudp\n"
    )

    def _patch_tshark(self, monkeypatch: pytest.MonkeyPatch, dump: str) -> None:
        def fake_run(tshark: str, *args: str) -> str:
            if args == ("--version",):
                return "TShark (Wireshark) 4.6.6 (Git)."
            if args == ("-G", "fields"):
                return dump
            return ""

        monkeypatch.setattr(fingerprint_module, "_run_tshark", fake_run)
        monkeypatch.setenv("TSHARK", "/usr/bin/true")

    def _prepare(self, tmp_path: Path) -> tuple[Path, Path]:
        config_file = tmp_path / "codegen.toml"
        config_file.write_text(
            '[tshark]\nversion = "4.6.6"\n[generate]\nprotocols = ["udp"]\nmulti = []\n',
            encoding="utf-8",
        )
        proto_dir = tmp_path / "proto"
        proto_dir.mkdir()
        return config_file, proto_dir

    def _argv(self, command: str, config_file: Path, proto_dir: Path) -> list[str]:
        return [
            command,
            "--config",
            str(config_file),
            "--proto-dir",
            str(proto_dir),
            "--packages-dir",
            str(config_file.parent / "packages"),
        ]

    def test_write_then_check_across_a_reshuffle_stays_in_sync(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Write under one dump order, check under another: no drift (#68)."""
        assert self.SHUFFLED_DUMP != SAMPLE_DUMP
        config_file, proto_dir = self._prepare(tmp_path)

        self._patch_tshark(monkeypatch, SAMPLE_DUMP)
        assert main(self._argv("write", config_file, proto_dir)) == 0
        capsys.readouterr()

        self._patch_tshark(monkeypatch, self.SHUFFLED_DUMP)
        assert main(self._argv("check", config_file, proto_dir)) == 0
        assert "in sync" in capsys.readouterr().out

    def test_shuffled_dumps_produce_byte_identical_artifacts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Both the fingerprint header and the emitted body are order-independent."""
        written: list[dict[str, str]] = []
        for dump in (SAMPLE_DUMP, self.SHUFFLED_DUMP):
            root = tmp_path / f"run{len(written)}"
            root.mkdir()
            config_file, proto_dir = self._prepare(root)
            self._patch_tshark(monkeypatch, dump)
            assert main(self._argv("write", config_file, proto_dir)) == 0
            capsys.readouterr()
            written.append(
                {
                    path.name: path.read_text(encoding="utf-8")
                    for path in sorted(proto_dir.iterdir())
                }
            )
        assert written[0] == written[1]
        # And the hash really is over canonical text, not tshark's raw stdout.
        header = parse_header(written[0]["udp.py"])
        assert header is not None
        assert (
            header.dump_sha256
            == make_fingerprint(canonicalize_dump(SAMPLE_DUMP), tshark_version="4.6.6").dump_sha256
        )


class TestGenerateDistributions:
    DUMP = (
        "P\tUser Datagram Protocol\tudp\n"
        "F\tSource Port\tudp.srcport\tFT_UINT16\tudp\tBASE_PT_UDP\t0x0\t\n"
        "P\tIEEE 802.11 wireless LAN\twlan\n"
        "F\tType\twlan.fc.type\tFT_UINT16\twlan\tBASE_DEC\t0x0\t\n"
    )

    def test_destinations_and_extras_map(self) -> None:
        config = _config(protocols=("udp",), extras=(("wireless", ("wlan",)),))
        dists, _warnings = generate_distributions(config, self.DUMP)
        assert set(dists) == {"core", "wireless"}
        core_names = {artifact.name for artifact in dists["core"]}
        assert core_names == {"udp.py", "udp.pyi", "_extras.py"}
        assert {artifact.name for artifact in dists["wireless"]} == {"wlan.py", "wlan.pyi"}
        extras_map = next(a for a in dists["core"] if a.name == "_extras.py")
        assert parse_header(extras_map.content) is not None
        assert '"wlan": "wireless",' in extras_map.content

    def test_empty_extras_still_emits_empty_map(self) -> None:
        config = _config(protocols=("udp",))
        dists, _warnings = generate_distributions(config, self.DUMP)
        assert set(dists) == {"core"}
        extras_map = next(a for a in dists["core"] if a.name == "_extras.py")
        assert "EXTRAS_MODULES: dict[str, str] = {}" in extras_map.content

    def test_collisions_detected_across_destinations(self) -> None:
        dump = (
            "P\tProto A\tab-c\n"
            "F\tX\tab-c.x\tFT_UINT8\tab-c\tBASE_DEC\t0x0\t\n"
            "P\tProto B\tab.c\n"
            "F\tX\tab.c.x\tFT_UINT8\tab.c\tBASE_DEC\t0x0\t\n"
        )
        config = _config(protocols=("ab-c",), extras=(("wireless", ("ab.c",)),))
        with pytest.raises(ValueError, match="collides"):
            generate_distributions(config, dump)

    def test_generate_artifacts_unchanged_for_psdsl_gen(self) -> None:
        config = _config(protocols=("udp",))
        artifacts, _warnings = generate_artifacts(config, self.DUMP)
        assert {artifact.name for artifact in artifacts} == {"udp.py", "udp.pyi"}


class TestMainMultiDest:
    def _patch_tshark(self, monkeypatch: pytest.MonkeyPatch, dump: str) -> None:
        monkeypatch.setattr(
            fingerprint_module,
            "_tshark_version_output",
            lambda tshark: "TShark (Wireshark) 4.6.6 (Git).",
        )
        monkeypatch.setattr(
            fingerprint_module,
            "_tshark_dumps",
            lambda tshark: (canonicalize_dump(dump), ""),
        )
        monkeypatch.setenv("TSHARK", "/usr/bin/true")

    def _write_repo_config(self, root: Path) -> Path:
        config = root / "codegen.toml"
        config.write_text(
            "[tshark]\nversion = '4.6.6'\n"
            "[generate]\nprotocols = ['udp']\n"
            "[extras.wireless]\nprotocols = ['wlan']\n",
            encoding="utf-8",
        )
        return config

    def _argv(self, command: str, config_file: Path, root: Path) -> list[str]:
        return [
            command,
            "--config",
            str(config_file),
            "--proto-dir",
            str(root / "src/remora/proto"),
            "--packages-dir",
            str(root / "packages"),
        ]

    def test_write_places_extras_under_packages(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch_tshark(monkeypatch, TestGenerateDistributions.DUMP)
        config_file = self._write_repo_config(tmp_path)
        assert main(self._argv("write", config_file, tmp_path)) == 0
        assert (tmp_path / "src/remora/proto/_extras.py").is_file()
        assert (tmp_path / "packages/remora-wireless/src/remora/proto/wlan.py").is_file()
        assert (tmp_path / "packages/remora-wireless/src/remora/proto/wlan.pyi").is_file()
        assert "5 artifact(s)" in capsys.readouterr().out

    def test_check_flags_missing_extras_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch_tshark(monkeypatch, TestGenerateDistributions.DUMP)
        config_file = self._write_repo_config(tmp_path)
        assert main(self._argv("write", config_file, tmp_path)) == 0
        capsys.readouterr()  # drain the write output so the check assertions cannot alias it
        assert main(self._argv("check", config_file, tmp_path)) == 0
        assert "5 artifact(s)" in capsys.readouterr().out

        shutil.rmtree(tmp_path / "packages/remora-wireless")
        assert main(self._argv("check", config_file, tmp_path)) == 1
        assert "remora-wireless" in capsys.readouterr().err

    def test_check_reports_a_stale_distribution_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Dropping ``[extras.wireless]`` must not make its tree invisible to drift."""
        self._patch_tshark(monkeypatch, TestGenerateDistributions.DUMP)
        config_file = self._write_repo_config(tmp_path)
        assert main(self._argv("write", config_file, tmp_path)) == 0
        capsys.readouterr()
        assert main(self._argv("check", config_file, tmp_path)) == 0
        capsys.readouterr()

        config_file.write_text(
            "[tshark]\nversion = '4.6.6'\n[generate]\nprotocols = ['udp']\n",
            encoding="utf-8",
        )
        # Regenerate core so the only remaining problem is the abandoned tree.
        assert main(self._argv("write", config_file, tmp_path)) == 0
        capsys.readouterr()
        assert main(self._argv("check", config_file, tmp_path)) == 1
        captured = capsys.readouterr()
        assert "remora-wireless" in captured.err
        assert "wlan.py" in captured.err

    def test_check_ignores_unfingerprinted_files_in_a_stale_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch_tshark(monkeypatch, TestGenerateDistributions.DUMP)
        config_file = self._write_repo_config(tmp_path)
        assert main(self._argv("write", config_file, tmp_path)) == 0
        stale = tmp_path / "packages/remora-wireless/src/remora/proto"
        for path in sorted(stale.iterdir()):
            path.unlink()
        (stale / "__init__.py").write_text("# hand-written\n", encoding="utf-8")
        config_file.write_text(
            "[tshark]\nversion = '4.6.6'\n[generate]\nprotocols = ['udp']\n",
            encoding="utf-8",
        )
        assert main(self._argv("write", config_file, tmp_path)) == 0
        assert main(self._argv("check", config_file, tmp_path)) == 0

    def test_check_reports_drift_inside_an_extra(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        self._patch_tshark(monkeypatch, TestGenerateDistributions.DUMP)
        config_file = self._write_repo_config(tmp_path)
        assert main(self._argv("write", config_file, tmp_path)) == 0
        drifted = tmp_path / "packages/remora-wireless/src/remora/proto/wlan.py"
        drifted.write_text(drifted.read_text(encoding="utf-8") + "# stale\n", encoding="utf-8")
        capsys.readouterr()
        assert main(self._argv("check", config_file, tmp_path)) == 1
        captured = capsys.readouterr()
        assert "wlan.py" in captured.err
        assert "# stale" in captured.err


def test_pyproject_declares_tomli_as_a_runtime_dependency() -> None:
    """On py3.10 ``import remora.codegen`` pulls in tomli, so it cannot be dev-only.

    A dev-group-only tomli means ``pip install remora`` on 3.10 raises
    ModuleNotFoundError from :mod:`remora.codegen.fingerprint`.
    """
    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    with pyproject.open("rb") as handle:
        data = tomllib.load(handle)
    dependencies = data["project"]["dependencies"]
    tomli_requirements = [dep for dep in dependencies if dep.startswith("tomli")]
    assert tomli_requirements, f"[project] dependencies must require tomli: {dependencies!r}"
    assert all("python_version < '3.11'" in dep for dep in tomli_requirements), tomli_requirements


def test_codegen_package_is_runnable_as_a_module() -> None:
    """``python -m remora.codegen`` needs a __main__ so runpy does not re-execute
    fingerprint.py (which the package __init__ already imported) and warn.

    The spec is only located, never imported: importing it runs the CLI.
    """
    assert importlib.util.find_spec("remora.codegen.__main__") is not None


def test_codegen_package_reexports() -> None:
    import remora.codegen as codegen

    for name in (
        "Artifact",
        "CheckReport",
        "CodegenConfig",
        "Fingerprint",
        "add_header",
        "check_artifacts",
        "generate_artifacts",
        "load_config",
        "make_fingerprint",
        "parse_header",
        "render_header",
    ):
        assert name in codegen.__all__
        assert getattr(codegen, name) is not None
