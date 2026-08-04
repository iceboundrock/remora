# Core Protocol Set Generation Implementation Plan (issue #19)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Populate `codegen.toml` with the ~30 core protocols, generate the fingerprinted artifacts under the pinned tshark 4.6.6, replace the five hand-written seed modules with generated output, and keep the whole CI gate green.

**Architecture:** All machinery already exists (`python -m remora.codegen write/check`, emitter, fingerprints, drift CI job). This issue is configuration + generation + integration: fill the config, run the generator in a CI-identical environment, adjust the two places that hard-code seed-only assumptions (the seed naming-convention test and the ruff gate), and re-export the new classes.

**Tech Stack:** Python/uv, tshark 4.6.6 via docker (`ubuntu:24.04` + `ppa:wireshark-dev/stable`, `--platform linux/amd64` to match the GitHub runner exactly).

## Global Constraints

- Pinned tshark stays **4.6.6** — verified 2026-08-04: `ppa:wireshark-dev/stable` publishes `4.6.6-1~ubuntu24.04.0~ppa1` for noble/amd64. The local Homebrew tshark is **4.6.7 and must not produce committed artifacts** (its dump-sha would fail the CI drift check). All `codegen write`/`check` runs happen inside docker.
- CI gate must pass: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy --strict src tests`, `uv run pytest` (integration tests use the local 4.6.7 tshark — that is fine; only codegen write/check is version-pinned).
- Generator behavior changes are **out of scope** (file emitter bugs as separate issues).
- `remora.__all__` stays exactly `{"Capture", "DNS", "ETH", "IP", "TCP", "UDP", "__version__"}` — `tests/test_package.py:16` pins it (M1 test, must pass unchanged).
- One PR, branch `feat/issue-19-core-protocols`, body `Closes #19`. Squash-merge workflow.
- Empirically verified beforehand (trial generation with local tshark 4.6.7, `$CLAUDE_JOB_DIR/tmp/gen5`):
  - Generated tcp/udp modules contain fields violating the seed naming convention (`mptcp.*`/`udplite.*` prefixes, hyphenated `tcp.completeness.syn-ack`), so `test_attr_names_follow_seed_naming_convention` **cannot pass** against generated modules and must be deleted (its own docstring documents it as a seed-only typo guard).
  - 13 generated lines exceed 100 columns (all E501, nothing else) and `ruff format` would rewrap 3 files → lint per-file-ignore + format exclude required.
  - All 30 protocol abbrevs exist in the dump; the 5 replaced modules keep every attr the tests use (`srcport`, `port`, `src`, `qry_name`, …) with identical mangled names.

---

### Task 1: Branch, `codegen.toml` core set, ruff policy for the generated tree

**Files:**
- Modify: `codegen.toml` (the `[generate]` table)
- Modify: `pyproject.toml` (ruff lint per-file-ignores + format exclude)

**Interfaces:**
- Produces: `codegen.toml` `[generate].protocols` — 30 abbrevs, consumed by `python -m remora.codegen write/check` (Task 3) and by the new sync test (Task 2). `[generate].multi` — the curated multi-value field set (exactly the 20 seed multi fields plus `ipv6.addr`, `sctp.port`).

- [ ] **Step 1: Create the branch**

```bash
git checkout -b feat/issue-19-core-protocols
```

- [ ] **Step 2: Fill in `codegen.toml [generate]`**

Replace the `[generate]` section (keep `[tshark] version = "4.6.6"` untouched):

```toml
[generate]
# tshark protocol abbrevs generated and committed under src/remora/proto/
# (the issue #19 core set). Every entry must exist in the pinned dump;
# `python -m remora.codegen write` errors loudly on a missing abbrev.
protocols = [
    "eth", "ip", "ipv6", "tcp", "udp", "dns",
    "http", "http2", "tls",
    "icmp", "icmpv6", "arp",
    "dhcp", "dhcpv6", "ntp", "ssh", "ftp", "smtp", "pop", "imap",
    "snmp", "sip", "rtp", "quic", "sctp",
    "gre", "vlan", "llc", "stp", "igmp",
]
# tshark field abbrevs that are multi-valued (`-G fields` has no multiplicity
# signal, so this set is curated by hand). Exactly the M1 seed multi set plus
# the obvious analogs ipv6.addr and sctp.port; extend deliberately, never
# speculatively — flipping a shipped scalar to multi changes its access type.
multi = [
    "eth.addr", "eth.ig", "eth.lg",
    "ip.addr", "ipv6.addr",
    "tcp.port", "udp.port", "sctp.port",
    "dns.qry.name", "dns.qry.type", "dns.qry.class",
    "dns.resp.name", "dns.resp.type", "dns.resp.class", "dns.resp.ttl",
    "dns.a", "dns.aaaa", "dns.cname", "dns.ns",
    "dns.ptr.domain_name", "dns.mx.mail_exchange", "dns.txt",
]
```

- [ ] **Step 3: Add the ruff policy for the generated tree to `pyproject.toml`**

After the existing `[tool.ruff.lint]` table add:

```toml
[tool.ruff.lint.per-file-ignores]
# Generated protocol tables (issue #19) keep one field entry per line no
# matter how long the abbrev is; the emitter never wraps (see the line-length
# note in src/remora/codegen/emit.py).
"src/remora/proto/*" = ["E501"]

[tool.ruff.format]
# Generated protocol modules are byte-exact emitter output; reformatting them
# would break `python -m remora.codegen check`. _meta.py and __init__.py ride
# along (they remain fully lint-checked, only the formatter skips them).
exclude = ["src/remora/proto/*.py", "src/remora/proto/*.pyi"]
```

- [ ] **Step 4: Verify the gate still passes on the untouched tree**

Run: `uv run ruff check . && uv run ruff format --check . && uv run pytest -m "not integration" -q`
Expected: all pass (config-only change; the drift check is not part of the local gate).

- [ ] **Step 5: Commit**

```bash
git add codegen.toml pyproject.toml
git commit -m "codegen: pin the issue-19 core protocol set and ruff policy for the generated tree"
```

---

### Task 2: Failing sync tests for the shipped protocol package

**Files:**
- Create: `tests/test_proto_package.py`

**Interfaces:**
- Consumes: `codegen.toml` `[generate].protocols` (Task 1); `mangle_protocol(abbrev: str) -> str` from `remora.codegen.emit`; `parse_header(source: str) -> Fingerprint | None` from `remora.codegen.fingerprint`.
- Produces: the executable form of three acceptance criteria — config is the single source of truth, every configured protocol is exported, no non-fingerprinted field tables remain.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_proto_package.py` with exactly:

```python
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
```

- [ ] **Step 2: Run them to verify they fail for the right reason**

Run: `uv run pytest tests/test_proto_package.py -v`
Expected: `test_config_lists_the_core_protocol_set` PASSES (config filled in Task 1); the other two FAIL — modules like `ipv6.py` missing / seed files lack fingerprint headers.

- [ ] **Step 3: Commit the red tests**

```bash
git add tests/test_proto_package.py
git commit -m "test: pin the shipped proto package to codegen.toml (red for issue #19)"
```

---

### Task 3: Generate the artifacts under the pinned tshark (docker)

**Files:**
- Create/overwrite: `src/remora/proto/<proto>.py` + `.pyi` for all 30 protocols (60 fingerprinted files; the five seed pairs are overwritten in place)

**Interfaces:**
- Consumes: `codegen.toml` (Task 1); `python -m remora.codegen write` / `check` (existing).
- Produces: the committed generated tree that Tasks 4–6 build on. Class names are the upper-cased module names: ETH, IP, IPV6, TCP, UDP, DNS, HTTP, HTTP2, TLS, ICMP, ICMPV6, ARP, DHCP, DHCPV6, NTP, SSH, FTP, SMTP, POP, IMAP, SNMP, SIP, RTP, QUIC, SCTP, GRE, VLAN, LLC, STP, IGMP.

- [ ] **Step 1: Pre-flight docker**

Run: `docker info >/dev/null && echo ok`
Expected: `ok`. If docker is not running, start Docker Desktop first (`open -a Docker` and wait).

- [ ] **Step 2: Generate + drift-check inside a CI-identical container**

From the repo root:

```bash
docker run --rm --platform linux/amd64 -v "$PWD":/work -w /work ubuntu:24.04 bash -euc '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get install -yq --no-install-recommends software-properties-common ca-certificates python3
  add-apt-repository -y ppa:wireshark-dev/stable
  apt-get install -yq --no-install-recommends tshark
  tshark --version | head -1
  PYTHONPATH=src python3 -m remora.codegen write
  PYTHONPATH=src python3 -m remora.codegen check
'
```

Expected output (in order): `TShark (Wireshark) 4.6.6 …`, possibly `warning: …: attribute name … already taken … field skipped` lines (collision skips are by design — record them for the PR body), `wrote 60 artifact(s)`, `codegen artifacts in sync (60 artifact(s) checked)`.
If the printed tshark version is not 4.6.6, STOP — the PPA moved; re-verify with the Launchpad API and escalate to the user before changing the pin.

- [ ] **Step 3: Sanity-check the result on the host**

```bash
ls src/remora/proto/ | wc -l          # expect 63 (60 artifacts + _meta.py + __init__.py + __pycache__)
head -6 src/remora/proto/tcp.py        # expect the remora-fingerprint header, tshark: 4.6.6
git status --short src/remora/proto | head
```

If files came back root-owned (host `ls -la` shows root), fix with:
`docker run --rm -v "$PWD":/work ubuntu:24.04 chown -R $(id -u):$(id -g) /work/src/remora/proto`

- [ ] **Step 4: Run the Task 2 tests**

Run: `uv run pytest tests/test_proto_package.py -v`
Expected: `test_no_hand_written_field_tables_remain` now PASSES; `test_every_configured_protocol_is_generated_and_exported` still FAILS (only on the `__all__` assert — Task 4).

- [ ] **Step 5: Commit the generated tree**

```bash
git add src/remora/proto
git commit -m "codegen: commit the generated core protocol set (tshark 4.6.6)"
```

---

### Task 4: Re-export the 30 protocol classes from `remora.proto`

**Files:**
- Modify: `src/remora/proto/__init__.py`

**Interfaces:**
- Consumes: the 30 generated modules (Task 3).
- Produces: `remora.proto.__all__` with all 30 class names; `remora/__init__.py` is **not touched** (its 5-class surface is pinned by `tests/test_package.py`).

- [ ] **Step 1: Rewrite `src/remora/proto/__init__.py`**

```python
"""Generated protocol classes — the issue-19 core set listed in codegen.toml."""

from remora.proto.arp import ARP
from remora.proto.dhcp import DHCP
from remora.proto.dhcpv6 import DHCPV6
from remora.proto.dns import DNS
from remora.proto.eth import ETH
from remora.proto.ftp import FTP
from remora.proto.gre import GRE
from remora.proto.http import HTTP
from remora.proto.http2 import HTTP2
from remora.proto.icmp import ICMP
from remora.proto.icmpv6 import ICMPV6
from remora.proto.igmp import IGMP
from remora.proto.imap import IMAP
from remora.proto.ip import IP
from remora.proto.ipv6 import IPV6
from remora.proto.llc import LLC
from remora.proto.ntp import NTP
from remora.proto.pop import POP
from remora.proto.quic import QUIC
from remora.proto.rtp import RTP
from remora.proto.sctp import SCTP
from remora.proto.sip import SIP
from remora.proto.smtp import SMTP
from remora.proto.snmp import SNMP
from remora.proto.ssh import SSH
from remora.proto.stp import STP
from remora.proto.tcp import TCP
from remora.proto.tls import TLS
from remora.proto.udp import UDP
from remora.proto.vlan import VLAN

__all__ = [
    "ARP",
    "DHCP",
    "DHCPV6",
    "DNS",
    "ETH",
    "FTP",
    "GRE",
    "HTTP",
    "HTTP2",
    "ICMP",
    "ICMPV6",
    "IGMP",
    "IMAP",
    "IP",
    "IPV6",
    "LLC",
    "NTP",
    "POP",
    "QUIC",
    "RTP",
    "SCTP",
    "SIP",
    "SMTP",
    "SNMP",
    "SSH",
    "STP",
    "TCP",
    "TLS",
    "UDP",
    "VLAN",
]
```

- [ ] **Step 2: Run the sync tests**

Run: `uv run pytest tests/test_proto_package.py tests/test_package.py -v`
Expected: all PASS (including `test_public_exports` — the top-level surface is unchanged).

- [ ] **Step 3: Commit**

```bash
git add src/remora/proto/__init__.py
git commit -m "core: re-export the generated core protocol classes from remora.proto"
```

---

### Task 5: Retire the seed-only naming test, run the full suite

**Files:**
- Modify: `tests/test_proto_seed.py` (delete one test method, refresh the module docstring)
- Possibly modify (contingency only): `tests/data/g_fields_sample.txt` + count assertions in `tests/test_codegen_parse.py`

**Interfaces:**
- Consumes: generated modules (Task 3).
- Produces: a green `uv run pytest` (integration included).

- [ ] **Step 1: Delete the seed-only typo guard**

In `tests/test_proto_seed.py`, delete the entire method `test_attr_names_follow_seed_naming_convention` (lines 99–114). Its docstring already declared the dots→underscores rule "a convention of the seed modules only, not part of the frozen compact-table format"; the generated modules legitimately violate it (`mptcp.*` fields under tcp keep their full abbrev; `tcp.completeness.syn-ack` mangles its hyphen to `_`).

- [ ] **Step 2: Refresh the module docstring**

Replace lines 1–10 of `tests/test_proto_seed.py` with:

```python
"""Pairing tests for the generated protocol modules (issues #13/#19).

Originally written against the hand-written M1 seeds, these tests are the
frozen-format contract and now run against the generated core-set modules:
each ``.pyi`` stub is parsed with ``ast`` and cross-checked against the
runtime ``_table_`` in both directions, so the pair cannot drift.

The ``assert_type`` calls are the static half of the acceptance criteria:
they are verified when mypy checks this file and are no-ops at runtime.
"""
```

- [ ] **Step 3: Run the full suite (integration included, local tshark 4.6.7)**

Run: `uv run pytest`
Expected: all pass. Two known possible failures, with fixes:

1. `tests/test_proto_seed.py` typing tests fail → the multi list or an attr is wrong in the generated tree; do NOT patch tests — go back to Task 1's multi list, regenerate (Task 3), rerun.
2. `tests/test_codegen_parse.py::…::test_mangling_reproduces_m1_seed_tables` KeyErrors, or exact-count assertions fail → version skew: committed tables are 4.6.6 but `tests/data/g_fields_sample.txt` was dumped from 4.6.7. Fix by regenerating the fixture under the pinned tshark inside docker:

```bash
docker run --rm --platform linux/amd64 -v "$PWD":/work -w /work ubuntu:24.04 bash -euc '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get install -yq --no-install-recommends software-properties-common ca-certificates python3
  add-apt-repository -y ppa:wireshark-dev/stable
  apt-get install -yq --no-install-recommends tshark
  TSHARK=$(command -v tshark) python3 tests/data/make_g_fields_sample.py
'
```

then update the exact record counts asserted in `tests/test_codegen_parse.py` to match the new fixture (run the failing tests; each failure message names the expected number), and update the "4.6.7" reference in `tests/data/make_g_fields_sample.py`'s docstring/AGENTS.md if the version noted there changes.

- [ ] **Step 4: Commit**

```bash
git add tests/test_proto_seed.py            # plus fixture/count files iff the contingency fired
git commit -m "test: retire the seed-only attr naming guard; pairing tests now cover generated modules"
```

---

### Task 6: Documentation sweep + full gate

**Files:**
- Modify: `README.md` (the codegen.toml paragraph), `AGENTS.md` (proto bullet + two invariants bullets), `src/remora/codegen/emit.py` (docstring note only — not code)

**Interfaces:** none (docs only).

- [ ] **Step 1: README**

In the fingerprint paragraph (~line 60), replace the tail sentence "That file also lists which protocols are generated and committed; that list is still empty while the M1 seeds are hand-written ([#19](https://github.com/iceboundrock/remora/issues/19) populates it)." with:

> That file also lists which protocols are generated and committed — the ~30-protocol core set ([#19](https://github.com/iceboundrock/remora/issues/19)) — plus the curated multi-value field set; regeneration must run under the pinned tshark (CI re-checks byte equality on every push).

- [ ] **Step 2: AGENTS.md**

1. In the `src/remora/proto/` bullet, replace the sentence beginning "The eth/ip/tcp/udp/dns modules are hand-written M1 seeds…" with:

> Protocol modules are generated artifacts (#19): `codegen.toml` lists the core set and the curated multi-value fields; regenerate with `uv run python -m remora.codegen write` under the pinned tshark (in practice inside docker: `ubuntu:24.04` + `ppa:wireshark-dev/stable`, since the pin tracks CI's PPA). Each generated `.py` has a sibling `.pyi` stub that shadows it for type checkers, declaring `Field[T]`/`MultiField[T]` per attribute; `_meta.py` and `__init__.py` are the only hand-written files, ruff ignores E501 under `proto/` and the formatter skips the tree so committed bytes stay emitter-exact.

2. In "Cross-cutting invariants", replace the first bullet with:

> - `tests/test_proto_seed.py` pairing tests are the frozen-format contract, now running against the generated core modules — keep them passing unmodified.

3. Replace the second bullet ("The seeds' dots→underscores attribute naming…") with:

> - Attribute names come from the frozen mangle policy (`src/remora/codegen/mangle.py`) at generation time; `_table_` stores the full tshark name precisely so nothing at runtime may re-derive tshark names from attribute names or vice versa.

- [ ] **Step 3: emit.py docstring**

In the module docstring's "Line length" paragraph, replace the final sentence ("Entries stay on one line by design; the lint policy … is deferred to the protocol-shipping issue (#19), where generated modules are actually committed.") with:

> Entries stay on one line by design; the shipped tree (issue #19) ignores E501 for ``src/remora/proto/*`` and excludes the directory from ruff format, so the committed bytes match this emitter exactly.

- [ ] **Step 4: Full CI gate**

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest
```

Expected: all four pass. Then re-run the docker drift check (Task 3 Step 2 command, `check` only — drop the `write` line) and expect `codegen artifacts in sync (60 artifact(s) checked)`.

- [ ] **Step 5: Commit**

```bash
git add README.md AGENTS.md src/remora/codegen/emit.py
git commit -m "docs: describe the generated core protocol set and its lint policy"
```

---

### Task 7: PR

- [ ] **Step 1: Push and open the PR**

```bash
git push -u origin feat/issue-19-core-protocols
gh pr create --title "codegen: generate core protocol set and replace seed modules" --body "$(cat <<'EOF'
Closes #19

## Summary
- `codegen.toml` now lists the 30-protocol core set and the curated multi-value field set (the M1 seed multi fields + `ipv6.addr`/`sctp.port`) — the single config the generator consumes
- 60 fingerprinted artifacts committed under `src/remora/proto/`, generated by pinned tshark 4.6.6 inside a CI-identical container (ubuntu 24.04 + ppa:wireshark-dev/stable, linux/amd64); in-container `python -m remora.codegen check` passes
- the five hand-written seed pairs are overwritten by generated output; `remora.proto` re-exports all 30 classes while the top-level `remora` surface is unchanged
- new `tests/test_proto_package.py` pins the package to `codegen.toml`: every configured protocol generated + exported, every artifact fingerprinted, nothing hand-written left
- retired `test_attr_names_follow_seed_naming_convention` — its docstring declared the dots→underscores rule a seed-only typo guard, and generated tcp/udp legitimately deviate (`mptcp.*` full-abbrev attrs, `tcp.completeness.syn-ack` hyphen); all other pairing/typing/e2e tests pass unchanged
- ruff: E501 ignored for `src/remora/proto/*`, formatter excludes the generated tree (committed bytes must stay emitter-exact for the drift check)

## Test plan
- [ ] `uv run pytest` (integration included, local tshark 4.6.7)
- [ ] `uv run mypy --strict src tests`, `uv run ruff check .`, `uv run ruff format --check .`
- [ ] docker drift check: `python -m remora.codegen check` → "codegen artifacts in sync (60 artifact(s) checked)"

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

(Update the "retired test" bullet and test-plan checkboxes to reflect what actually happened — e.g. whether the fixture contingency in Task 5 fired; check the boxes only after the commands really ran.)

- [ ] **Step 2: Watch CI**

Run: `gh pr checks --watch`
Expected: all matrix jobs + `codegen-drift` green. If `codegen-drift` fails with a version mismatch, the PPA moved between generation and CI — regenerate (Task 3) after re-verifying the published version.
