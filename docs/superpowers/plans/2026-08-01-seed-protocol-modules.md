# Seed Protocol Modules (eth, ip, tcp, udp, dns) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hand-write five seed protocol modules (`eth`, `ip`, `tcp`, `udp`, `dns`) as `.py`/`.pyi` pairs in the frozen compact-table format, plus a pairing test that keeps each pair honest (issue #13).

**Architecture:** Each `.py` module is a dumb compact table — `class IP(ProtocolBase)` with `_proto_` and `_table_ = {attr: (tshark_name, ftype, multi)}` — exactly what the M2 generator (issue #14) will emit. The sibling `.pyi` shadows it for type checkers, declaring one `Field[T]`/`MultiField[T]` descriptor annotation per attribute so `IP.src` types as `FieldRef[IPv4Address]` and `pkt[IP].src` as `IPv4Address | None`. A parametrized test parses each `.pyi` with `ast` and cross-checks it against the runtime `_table_` in both directions, including multiplicity, ftype→Python-type agreement, and attribute-name derivation.

**Tech Stack:** Python ≥3.10, pytest, mypy --strict, ruff. No new dependencies.

## Global Constraints

- `requires-python = ">=3.10"` — no 3.11+ syntax.
- CI gate: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy --strict src tests`, `uv run pytest` must all pass.
- Line length 100 (ruff).
- The `.py` table format is frozen by `src/remora/proto/_meta.py`: `FieldSpec = tuple[str, str, int]` (tshark_name, ftype, multi as 0/1), `FieldTable = dict[str, FieldSpec]`; classes set only `_proto_` and `_table_`. Declare tables as `_table_: ClassVar[FieldTable] = {...}` — ruff RUF012 rejects a bare mutable class-attribute assignment.
- Seed naming convention (a typo guard for the hand-written modules, **not** part of the frozen format): `attr == tshark_name.removeprefix(f"{proto}.").replace(".", "_")` (e.g. `dns.qry.name` → `qry_name`). Generated modules (M2, issue #14) may deviate — e.g. to escape Python keywords — which is exactly why `_meta.py` stores the full tshark name instead of deriving it.
- Every ftype used must be a key of `remora.values.FTYPE_TABLE` (no silent str fallback).
- Work on branch `feat/13-seed-protocols`; commit per task.

## File Structure

- `src/remora/proto/eth.py` / `eth.pyi` — `ETH` (11 fields)
- `src/remora/proto/ip.py` / `ip.pyi` — `IP` (19 fields)
- `src/remora/proto/tcp.py` / `tcp.pyi` — `TCP` (27 fields)
- `src/remora/proto/udp.py` / `udp.pyi` — `UDP` (10 fields)
- `src/remora/proto/dns.py` / `dns.pyi` — `DNS` (29 fields)
- `src/remora/proto/__init__.py` — re-export the five classes via `__all__`
- `tests/test_proto_seed.py` — pairing tests (parametrized over all five) + acceptance tests

---

### Task 1: Pairing-test harness + ETH seed module

**Files:**
- Create: `tests/test_proto_seed.py`
- Create: `src/remora/proto/eth.py`
- Create: `src/remora/proto/eth.pyi`

**Interfaces:**
- Consumes: `remora.proto._meta.ProtocolBase`, `remora.values.get_info`/`FTYPE_TABLE`, `remora.fields.Field`/`MultiField`.
- Produces: `remora.proto.eth.ETH`; the `SEEDS` registry and `stub_fields()` helper in `tests/test_proto_seed.py` that Tasks 2–5 extend.

- [ ] **Step 1: Create the branch**

```bash
git checkout -b feat/13-seed-protocols
```

- [ ] **Step 2: Write the pairing test with the ETH entry**

Create `tests/test_proto_seed.py`:

```python
"""Pairing tests for the hand-written seed protocol modules (issue #13).

The seed ``.py`` modules are dumb compact tables in the frozen format the M2
generator (issue #14) will emit; the sibling ``.pyi`` stubs shadow them for
type checkers. These tests parse each stub with ``ast`` and cross-check it
against the runtime ``_table_`` in both directions, so the pair cannot drift.

The ``assert_type`` calls are the static half of the acceptance criteria:
they are verified when mypy checks this file and are no-ops at runtime.
"""

from __future__ import annotations

import ast
import pathlib
from types import ModuleType

import pytest

from remora import values
from remora.proto import eth as eth_mod
from remora.proto._meta import ProtocolBase

SEEDS: list[tuple[ModuleType, type[ProtocolBase]]] = [
    (eth_mod, eth_mod.ETH),
]

seed_params = pytest.mark.parametrize(
    ("module", "cls"), SEEDS, ids=[cls.__name__ for _, cls in SEEDS]
)


def stub_fields(module: ModuleType) -> dict[str, tuple[str, str]]:
    """Parse a module's ``.pyi``: attr name -> (descriptor name, inner type name)."""
    assert module.__file__ is not None
    stub_path = pathlib.Path(module.__file__).with_suffix(".pyi")
    tree = ast.parse(stub_path.read_text(), filename=str(stub_path))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
    assert len(classes) == 1, f"expected exactly one class in {stub_path}"
    fields: dict[str, tuple[str, str]] = {}
    for item in classes[0].body:
        if not isinstance(item, ast.AnnAssign):
            continue
        assert isinstance(item.target, ast.Name)
        annotation = item.annotation
        assert isinstance(annotation, ast.Subscript), f"{item.target.id}: not Field[T]"
        assert isinstance(annotation.value, ast.Name)
        assert isinstance(annotation.slice, ast.Name)
        fields[item.target.id] = (annotation.value.id, annotation.slice.id)
    return fields


@seed_params
class TestStubTablePairing:
    def test_stub_and_table_declare_the_same_attributes(
        self, module: ModuleType, cls: type[ProtocolBase]
    ) -> None:
        stub_attrs = set(stub_fields(module))
        table_attrs = set(cls._table_)
        assert stub_attrs - table_attrs == set(), "stub declares fields missing from _table_"
        assert table_attrs - stub_attrs == set(), "_table_ has fields missing from the stub"

    def test_multiplicity_matches_descriptor_class(
        self, module: ModuleType, cls: type[ProtocolBase]
    ) -> None:
        stubs = stub_fields(module)
        for attr, (_, _, multi) in cls._table_.items():
            expected = "MultiField" if multi else "Field"
            assert stubs[attr][0] == expected, (
                f"{attr}: multi={multi} but stub says {stubs[attr][0]}"
            )

    def test_stub_inner_type_matches_ftype(
        self, module: ModuleType, cls: type[ProtocolBase]
    ) -> None:
        stubs = stub_fields(module)
        for attr, (_, ftype, _) in cls._table_.items():
            expected = values.get_info(ftype).py_type.__name__
            assert stubs[attr][1] == expected, f"{attr}: {ftype} parses to {expected}"

    def test_every_ftype_is_known(self, module: ModuleType, cls: type[ProtocolBase]) -> None:
        for attr, (_, ftype, _) in cls._table_.items():
            assert ftype in values.FTYPE_TABLE, f"{attr}: unknown ftype {ftype!r}"

    def test_attr_names_follow_seed_naming_convention(
        self, module: ModuleType, cls: type[ProtocolBase]
    ) -> None:
        """Seed-only convention (typo guard), not part of the frozen format."""
        prefix = f"{cls._proto_}."
        for attr, (tshark_name, _, _) in cls._table_.items():
            assert tshark_name.startswith(prefix), f"{attr}: {tshark_name!r} lacks {prefix!r}"
            derived = tshark_name.removeprefix(prefix).replace(".", "_")
            assert attr == derived, f"{attr!r} != derived {derived!r}"

    def test_proto_matches_module_name(self, module: ModuleType, cls: type[ProtocolBase]) -> None:
        assert module.__name__.rsplit(".", 1)[-1] == cls._proto_
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/test_proto_seed.py -v`
Expected: FAIL at import with `ModuleNotFoundError: No module named 'remora.proto.eth'`

- [ ] **Step 4: Write the ETH runtime module**

Create `src/remora/proto/eth.py`:

```python
"""Ethernet seed protocol — compact-table format (frozen; matches the M2 emitter)."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["ETH"]


class ETH(ProtocolBase):
    """Ethernet II / 802.3 (tshark layer ``eth``)."""

    _proto_ = "eth"
    _table_: ClassVar[FieldTable] = {
        "dst": ("eth.dst", "FT_ETHER", 0),
        "src": ("eth.src", "FT_ETHER", 0),
        "addr": ("eth.addr", "FT_ETHER", 1),
        "ig": ("eth.ig", "FT_BOOLEAN", 1),
        "lg": ("eth.lg", "FT_BOOLEAN", 1),
        "type": ("eth.type", "FT_UINT16", 0),
        "len": ("eth.len", "FT_UINT16", 0),
        "padding": ("eth.padding", "FT_BYTES", 0),
        "trailer": ("eth.trailer", "FT_BYTES", 0),
        "fcs": ("eth.fcs", "FT_UINT32", 0),
        "fcs_status": ("eth.fcs.status", "FT_UINT8", 0),
    }
```

- [ ] **Step 5: Write the ETH stub**

Create `src/remora/proto/eth.pyi`:

```python
from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase


class ETH(ProtocolBase):
    dst: Field[bytes]
    src: Field[bytes]
    addr: MultiField[bytes]
    ig: MultiField[bool]
    lg: MultiField[bool]
    type: Field[int]
    len: Field[int]
    padding: Field[bytes]
    trailer: Field[bytes]
    fcs: Field[int]
    fcs_status: Field[int]
```

- [ ] **Step 6: Run the pairing tests to verify they pass**

Run: `uv run pytest tests/test_proto_seed.py -v`
Expected: PASS (6 tests, id `ETH`)

- [ ] **Step 7: Run the full gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest`
Expected: all clean. If `ruff format --check` complains about the new files, run `uv run ruff format` and re-check.

- [ ] **Step 8: Commit**

```bash
git add tests/test_proto_seed.py src/remora/proto/eth.py src/remora/proto/eth.pyi
git commit -m "core: add ETH seed protocol module and .py/.pyi pairing test"
```

---

### Task 2: IP seed module

**Files:**
- Create: `src/remora/proto/ip.py`
- Create: `src/remora/proto/ip.pyi`
- Modify: `tests/test_proto_seed.py` (add the IP entry to `SEEDS`)

**Interfaces:**
- Consumes: `SEEDS` registry from Task 1.
- Produces: `remora.proto.ip.IP` with `src`/`dst` as `Field[IPv4Address]`, `addr` as `MultiField[IPv4Address]`.

- [ ] **Step 1: Add IP to the test registry**

In `tests/test_proto_seed.py`, add the import (keep imports alphabetized: `eth`, `ip`):

```python
from remora.proto import ip as ip_mod
```

and extend `SEEDS`:

```python
SEEDS: list[tuple[ModuleType, type[ProtocolBase]]] = [
    (eth_mod, eth_mod.ETH),
    (ip_mod, ip_mod.IP),
]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_proto_seed.py -v`
Expected: FAIL at import with `ModuleNotFoundError: No module named 'remora.proto.ip'`

- [ ] **Step 3: Write the IP runtime module**

Create `src/remora/proto/ip.py`:

```python
"""IPv4 seed protocol — compact-table format (frozen; matches the M2 emitter)."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["IP"]


class IP(ProtocolBase):
    """Internet Protocol version 4 (tshark layer ``ip``)."""

    _proto_ = "ip"
    _table_: ClassVar[FieldTable] = {
        "version": ("ip.version", "FT_UINT8", 0),
        "hdr_len": ("ip.hdr_len", "FT_UINT8", 0),
        "dsfield": ("ip.dsfield", "FT_UINT8", 0),
        "dsfield_dscp": ("ip.dsfield.dscp", "FT_UINT8", 0),
        "dsfield_ecn": ("ip.dsfield.ecn", "FT_UINT8", 0),
        "len": ("ip.len", "FT_UINT16", 0),
        "id": ("ip.id", "FT_UINT16", 0),
        "flags": ("ip.flags", "FT_UINT8", 0),
        "flags_rb": ("ip.flags.rb", "FT_BOOLEAN", 0),
        "flags_df": ("ip.flags.df", "FT_BOOLEAN", 0),
        "flags_mf": ("ip.flags.mf", "FT_BOOLEAN", 0),
        "frag_offset": ("ip.frag_offset", "FT_UINT16", 0),
        "ttl": ("ip.ttl", "FT_UINT8", 0),
        "proto": ("ip.proto", "FT_UINT8", 0),
        "checksum": ("ip.checksum", "FT_UINT16", 0),
        "checksum_status": ("ip.checksum.status", "FT_UINT8", 0),
        "src": ("ip.src", "FT_IPv4", 0),
        "dst": ("ip.dst", "FT_IPv4", 0),
        "addr": ("ip.addr", "FT_IPv4", 1),
    }
```

- [ ] **Step 4: Write the IP stub**

Create `src/remora/proto/ip.pyi`:

```python
from ipaddress import IPv4Address

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase


class IP(ProtocolBase):
    version: Field[int]
    hdr_len: Field[int]
    dsfield: Field[int]
    dsfield_dscp: Field[int]
    dsfield_ecn: Field[int]
    len: Field[int]
    id: Field[int]
    flags: Field[int]
    flags_rb: Field[bool]
    flags_df: Field[bool]
    flags_mf: Field[bool]
    frag_offset: Field[int]
    ttl: Field[int]
    proto: Field[int]
    checksum: Field[int]
    checksum_status: Field[int]
    src: Field[IPv4Address]
    dst: Field[IPv4Address]
    addr: MultiField[IPv4Address]
```

- [ ] **Step 5: Run the pairing tests to verify they pass**

Run: `uv run pytest tests/test_proto_seed.py -v`
Expected: PASS (12 tests: ids `ETH`, `IP`)

- [ ] **Step 6: Run the full gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest`
Expected: all clean.

- [ ] **Step 7: Commit**

```bash
git add src/remora/proto/ip.py src/remora/proto/ip.pyi tests/test_proto_seed.py
git commit -m "core: add IP seed protocol module"
```

---

### Task 3: TCP seed module

**Files:**
- Create: `src/remora/proto/tcp.py`
- Create: `src/remora/proto/tcp.pyi`
- Modify: `tests/test_proto_seed.py` (add the TCP entry to `SEEDS`)

**Interfaces:**
- Consumes: `SEEDS` registry from Task 1.
- Produces: `remora.proto.tcp.TCP` with `port` as `MultiField[int]`, `srcport`/`dstport` as `Field[int]`, `time_delta`/`time_relative` as `Field[timedelta]`.

- [ ] **Step 1: Add TCP to the test registry**

In `tests/test_proto_seed.py`, add:

```python
from remora.proto import tcp as tcp_mod
```

and extend `SEEDS`:

```python
SEEDS: list[tuple[ModuleType, type[ProtocolBase]]] = [
    (eth_mod, eth_mod.ETH),
    (ip_mod, ip_mod.IP),
    (tcp_mod, tcp_mod.TCP),
]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_proto_seed.py -v`
Expected: FAIL at import with `ModuleNotFoundError: No module named 'remora.proto.tcp'`

- [ ] **Step 3: Write the TCP runtime module**

Create `src/remora/proto/tcp.py`:

```python
"""TCP seed protocol — compact-table format (frozen; matches the M2 emitter)."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["TCP"]


class TCP(ProtocolBase):
    """Transmission Control Protocol (tshark layer ``tcp``)."""

    _proto_ = "tcp"
    _table_: ClassVar[FieldTable] = {
        "srcport": ("tcp.srcport", "FT_UINT16", 0),
        "dstport": ("tcp.dstport", "FT_UINT16", 0),
        "port": ("tcp.port", "FT_UINT16", 1),
        "stream": ("tcp.stream", "FT_UINT32", 0),
        "len": ("tcp.len", "FT_UINT32", 0),
        "seq": ("tcp.seq", "FT_UINT32", 0),
        "nxtseq": ("tcp.nxtseq", "FT_UINT32", 0),
        "ack": ("tcp.ack", "FT_UINT32", 0),
        "hdr_len": ("tcp.hdr_len", "FT_UINT8", 0),
        "flags": ("tcp.flags", "FT_UINT16", 0),
        "flags_fin": ("tcp.flags.fin", "FT_BOOLEAN", 0),
        "flags_syn": ("tcp.flags.syn", "FT_BOOLEAN", 0),
        "flags_reset": ("tcp.flags.reset", "FT_BOOLEAN", 0),
        "flags_push": ("tcp.flags.push", "FT_BOOLEAN", 0),
        "flags_ack": ("tcp.flags.ack", "FT_BOOLEAN", 0),
        "flags_urg": ("tcp.flags.urg", "FT_BOOLEAN", 0),
        "flags_ece": ("tcp.flags.ece", "FT_BOOLEAN", 0),
        "flags_cwr": ("tcp.flags.cwr", "FT_BOOLEAN", 0),
        "window_size": ("tcp.window_size", "FT_UINT32", 0),
        "window_size_value": ("tcp.window_size_value", "FT_UINT16", 0),
        "checksum": ("tcp.checksum", "FT_UINT16", 0),
        "checksum_status": ("tcp.checksum.status", "FT_UINT8", 0),
        "urgent_pointer": ("tcp.urgent_pointer", "FT_UINT16", 0),
        "options": ("tcp.options", "FT_BYTES", 0),
        "payload": ("tcp.payload", "FT_BYTES", 0),
        "time_delta": ("tcp.time_delta", "FT_RELATIVE_TIME", 0),
        "time_relative": ("tcp.time_relative", "FT_RELATIVE_TIME", 0),
    }
```

- [ ] **Step 4: Write the TCP stub**

Create `src/remora/proto/tcp.pyi`:

```python
from datetime import timedelta

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase


class TCP(ProtocolBase):
    srcport: Field[int]
    dstport: Field[int]
    port: MultiField[int]
    stream: Field[int]
    len: Field[int]
    seq: Field[int]
    nxtseq: Field[int]
    ack: Field[int]
    hdr_len: Field[int]
    flags: Field[int]
    flags_fin: Field[bool]
    flags_syn: Field[bool]
    flags_reset: Field[bool]
    flags_push: Field[bool]
    flags_ack: Field[bool]
    flags_urg: Field[bool]
    flags_ece: Field[bool]
    flags_cwr: Field[bool]
    window_size: Field[int]
    window_size_value: Field[int]
    checksum: Field[int]
    checksum_status: Field[int]
    urgent_pointer: Field[int]
    options: Field[bytes]
    payload: Field[bytes]
    time_delta: Field[timedelta]
    time_relative: Field[timedelta]
```

- [ ] **Step 5: Run the pairing tests to verify they pass**

Run: `uv run pytest tests/test_proto_seed.py -v`
Expected: PASS (18 tests: ids `ETH`, `IP`, `TCP`)

- [ ] **Step 6: Run the full gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest`
Expected: all clean.

- [ ] **Step 7: Commit**

```bash
git add src/remora/proto/tcp.py src/remora/proto/tcp.pyi tests/test_proto_seed.py
git commit -m "core: add TCP seed protocol module"
```

---

### Task 4: UDP seed module

**Files:**
- Create: `src/remora/proto/udp.py`
- Create: `src/remora/proto/udp.pyi`
- Modify: `tests/test_proto_seed.py` (add the UDP entry to `SEEDS`)

**Interfaces:**
- Consumes: `SEEDS` registry from Task 1.
- Produces: `remora.proto.udp.UDP` with `port` as `MultiField[int]`.

- [ ] **Step 1: Add UDP to the test registry**

In `tests/test_proto_seed.py`, add:

```python
from remora.proto import udp as udp_mod
```

and extend `SEEDS`:

```python
SEEDS: list[tuple[ModuleType, type[ProtocolBase]]] = [
    (eth_mod, eth_mod.ETH),
    (ip_mod, ip_mod.IP),
    (tcp_mod, tcp_mod.TCP),
    (udp_mod, udp_mod.UDP),
]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_proto_seed.py -v`
Expected: FAIL at import with `ModuleNotFoundError: No module named 'remora.proto.udp'`

- [ ] **Step 3: Write the UDP runtime module**

Create `src/remora/proto/udp.py`:

```python
"""UDP seed protocol — compact-table format (frozen; matches the M2 emitter)."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["UDP"]


class UDP(ProtocolBase):
    """User Datagram Protocol (tshark layer ``udp``)."""

    _proto_ = "udp"
    _table_: ClassVar[FieldTable] = {
        "srcport": ("udp.srcport", "FT_UINT16", 0),
        "dstport": ("udp.dstport", "FT_UINT16", 0),
        "port": ("udp.port", "FT_UINT16", 1),
        "length": ("udp.length", "FT_UINT16", 0),
        "checksum": ("udp.checksum", "FT_UINT16", 0),
        "checksum_status": ("udp.checksum.status", "FT_UINT8", 0),
        "stream": ("udp.stream", "FT_UINT32", 0),
        "payload": ("udp.payload", "FT_BYTES", 0),
        "time_delta": ("udp.time_delta", "FT_RELATIVE_TIME", 0),
        "time_relative": ("udp.time_relative", "FT_RELATIVE_TIME", 0),
    }
```

- [ ] **Step 4: Write the UDP stub**

Create `src/remora/proto/udp.pyi`:

```python
from datetime import timedelta

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase


class UDP(ProtocolBase):
    srcport: Field[int]
    dstport: Field[int]
    port: MultiField[int]
    length: Field[int]
    checksum: Field[int]
    checksum_status: Field[int]
    stream: Field[int]
    payload: Field[bytes]
    time_delta: Field[timedelta]
    time_relative: Field[timedelta]
```

- [ ] **Step 5: Run the pairing tests to verify they pass**

Run: `uv run pytest tests/test_proto_seed.py -v`
Expected: PASS (24 tests: ids `ETH`, `IP`, `TCP`, `UDP`)

- [ ] **Step 6: Run the full gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest`
Expected: all clean.

- [ ] **Step 7: Commit**

```bash
git add src/remora/proto/udp.py src/remora/proto/udp.pyi tests/test_proto_seed.py
git commit -m "core: add UDP seed protocol module"
```

---

### Task 5: DNS seed module

**Files:**
- Create: `src/remora/proto/dns.py`
- Create: `src/remora/proto/dns.pyi`
- Modify: `tests/test_proto_seed.py` (add the DNS entry to `SEEDS`)

**Interfaces:**
- Consumes: `SEEDS` registry from Task 1.
- Produces: `remora.proto.dns.DNS` with multi-valued record fields (`a`, `aaaa`, `cname`, `qry_name`, `resp_name`, …).

- [ ] **Step 1: Add DNS to the test registry**

In `tests/test_proto_seed.py`, add the import (alphabetical: `dns` sorts first):

```python
from remora.proto import dns as dns_mod
```

and extend `SEEDS`:

```python
SEEDS: list[tuple[ModuleType, type[ProtocolBase]]] = [
    (eth_mod, eth_mod.ETH),
    (ip_mod, ip_mod.IP),
    (tcp_mod, tcp_mod.TCP),
    (udp_mod, udp_mod.UDP),
    (dns_mod, dns_mod.DNS),
]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_proto_seed.py -v`
Expected: FAIL at import with `ModuleNotFoundError: No module named 'remora.proto.dns'`

- [ ] **Step 3: Write the DNS runtime module**

Create `src/remora/proto/dns.py`. Query/answer record fields are multi-valued: a DNS
message carries any number of queries and resource records, and tshark emits one
occurrence per record.

```python
"""DNS seed protocol — compact-table format (frozen; matches the M2 emitter)."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["DNS"]


class DNS(ProtocolBase):
    """Domain Name System (tshark layer ``dns``)."""

    _proto_ = "dns"
    _table_: ClassVar[FieldTable] = {
        "id": ("dns.id", "FT_UINT16", 0),
        "flags": ("dns.flags", "FT_UINT16", 0),
        "flags_response": ("dns.flags.response", "FT_BOOLEAN", 0),
        "flags_opcode": ("dns.flags.opcode", "FT_UINT16", 0),
        "flags_authoritative": ("dns.flags.authoritative", "FT_BOOLEAN", 0),
        "flags_recdesired": ("dns.flags.recdesired", "FT_BOOLEAN", 0),
        "flags_recavail": ("dns.flags.recavail", "FT_BOOLEAN", 0),
        "flags_rcode": ("dns.flags.rcode", "FT_UINT16", 0),
        "count_queries": ("dns.count.queries", "FT_UINT16", 0),
        "count_answers": ("dns.count.answers", "FT_UINT16", 0),
        "count_auth_rr": ("dns.count.auth_rr", "FT_UINT16", 0),
        "count_add_rr": ("dns.count.add_rr", "FT_UINT16", 0),
        "qry_name": ("dns.qry.name", "FT_STRING", 1),
        "qry_type": ("dns.qry.type", "FT_UINT16", 1),
        "qry_class": ("dns.qry.class", "FT_UINT16", 1),
        "resp_name": ("dns.resp.name", "FT_STRING", 1),
        "resp_type": ("dns.resp.type", "FT_UINT16", 1),
        "resp_class": ("dns.resp.class", "FT_UINT16", 1),
        "resp_ttl": ("dns.resp.ttl", "FT_UINT32", 1),
        "a": ("dns.a", "FT_IPv4", 1),
        "aaaa": ("dns.aaaa", "FT_IPv6", 1),
        "cname": ("dns.cname", "FT_STRING", 1),
        "ns": ("dns.ns", "FT_STRING", 1),
        "ptr_domain_name": ("dns.ptr.domain_name", "FT_STRING", 1),
        "mx_mail_exchange": ("dns.mx.mail_exchange", "FT_STRING", 1),
        "txt": ("dns.txt", "FT_STRING", 1),
        "response_in": ("dns.response_in", "FT_FRAMENUM", 0),
        "response_to": ("dns.response_to", "FT_FRAMENUM", 0),
        "time": ("dns.time", "FT_RELATIVE_TIME", 0),
    }
```

- [ ] **Step 4: Write the DNS stub**

Create `src/remora/proto/dns.pyi`:

```python
from datetime import timedelta
from ipaddress import IPv4Address, IPv6Address

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase


class DNS(ProtocolBase):
    id: Field[int]
    flags: Field[int]
    flags_response: Field[bool]
    flags_opcode: Field[int]
    flags_authoritative: Field[bool]
    flags_recdesired: Field[bool]
    flags_recavail: Field[bool]
    flags_rcode: Field[int]
    count_queries: Field[int]
    count_answers: Field[int]
    count_auth_rr: Field[int]
    count_add_rr: Field[int]
    qry_name: MultiField[str]
    qry_type: MultiField[int]
    qry_class: MultiField[int]
    resp_name: MultiField[str]
    resp_type: MultiField[int]
    resp_class: MultiField[int]
    resp_ttl: MultiField[int]
    a: MultiField[IPv4Address]
    aaaa: MultiField[IPv6Address]
    cname: MultiField[str]
    ns: MultiField[str]
    ptr_domain_name: MultiField[str]
    mx_mail_exchange: MultiField[str]
    txt: MultiField[str]
    response_in: Field[int]
    response_to: Field[int]
    time: Field[timedelta]
```

- [ ] **Step 5: Run the pairing tests to verify they pass**

Run: `uv run pytest tests/test_proto_seed.py -v`
Expected: PASS (30 tests: ids `ETH`, `IP`, `TCP`, `UDP`, `DNS`)

- [ ] **Step 6: Run the full gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest`
Expected: all clean.

- [ ] **Step 7: Commit**

```bash
git add src/remora/proto/dns.py src/remora/proto/dns.pyi tests/test_proto_seed.py
git commit -m "core: add DNS seed protocol module"
```

---

### Task 6: Package re-exports + acceptance tests

**Files:**
- Modify: `src/remora/proto/__init__.py`
- Modify: `tests/test_proto_seed.py` (append acceptance test classes)

**Interfaces:**
- Consumes: all five seed classes; `remora.fields.FieldRef`/`Packet`; `remora.expr.Comparison`; `conftest.FakePacket`.
- Produces: `from remora.proto import DNS, ETH, IP, TCP, UDP` for consumers (issue #15's Capture API).

- [ ] **Step 1: Write the failing acceptance tests**

Append to `tests/test_proto_seed.py`. Add these imports at the top (the `remora.proto`
package import will fail until Step 3):

```python
from ipaddress import IPv4Address
from typing import TypeVar, cast

from typing_extensions import assert_type

from conftest import FakePacket
from remora.expr import Comparison
from remora.fields import FieldRef, Packet
from remora.proto import DNS, IP, TCP

P = TypeVar("P", bound=ProtocolBase)
```

and append the test code:

```python
class FullFakePacket:
    """Packet test double: raw access plus ``pkt[Proto]`` typed views."""

    def __init__(self, data: dict[str, tuple[str, ...]]) -> None:
        self._data = data

    def get_raw(self, field_name: str) -> tuple[str, ...]:
        return self._data.get(field_name, ())

    def __getitem__(self, proto: type[P]) -> P:
        return proto(self)


def check_packet_protocol_typing(pkt: Packet) -> None:
    """Static half of the ``pkt[TCP]`` acceptance criterion; body checked by mypy."""
    assert_type(pkt[TCP].srcport, int | None)
    assert_type(pkt[IP].src, IPv4Address | None)
    assert_type(pkt[TCP].port, tuple[int, ...])


class TestAcceptance:
    """Runtime + static checks for the issue #13 acceptance criteria."""

    def test_ip_src_class_access_is_field_ref(self) -> None:
        ref = IP.src
        assert isinstance(ref, FieldRef)
        assert ref.name == "ip.src"
        assert ref.ftype == "FT_IPv4"
        assert_type(IP.src, FieldRef[IPv4Address])

    def test_ip_instance_access_parses_or_none(self) -> None:
        view = IP(FakePacket({"ip.src": ("10.0.0.1",)}))
        assert view.src == IPv4Address("10.0.0.1")
        assert view.dst is None
        assert_type(view.src, IPv4Address | None)

    def test_tcp_port_is_multi_valued(self) -> None:
        view = TCP(FakePacket({"tcp.port": ("443", "51234")}))
        assert view.port == (443, 51234)
        assert TCP(FakePacket({})).port == ()
        assert_type(view.port, tuple[int, ...])

    def test_tcp_port_comparison_builds_expr(self) -> None:
        e = TCP.port == 443
        assert isinstance(e, Comparison)
        assert e.field.name == "tcp.port"
        assert_type(e, Comparison)

    def test_dns_answers_are_tuples(self) -> None:
        view = DNS(FakePacket({"dns.a": ("1.2.3.4", "5.6.7.8")}))
        assert view.a == (IPv4Address("1.2.3.4"), IPv4Address("5.6.7.8"))

    def test_packet_view_access(self) -> None:
        pkt = FullFakePacket({"tcp.srcport": ("443",)})
        view = pkt[TCP]
        assert view.srcport == 443
        assert_type(view.srcport, int | None)
        check_packet_protocol_typing(cast(Packet, pkt))
```

- [ ] **Step 2: Run the tests to verify the new ones fail**

Run: `uv run pytest tests/test_proto_seed.py -v`
Expected: FAIL at import with `ImportError: cannot import name 'DNS' from 'remora.proto'`

- [ ] **Step 3: Add the package re-exports**

Replace `src/remora/proto/__init__.py` with:

```python
"""Protocol classes: hand-written seeds (issue #13) now, generated (issue #14) later."""

from remora.proto.dns import DNS
from remora.proto.eth import ETH
from remora.proto.ip import IP
from remora.proto.tcp import TCP
from remora.proto.udp import UDP

__all__ = ["DNS", "ETH", "IP", "TCP", "UDP"]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_proto_seed.py -v`
Expected: PASS (36 tests)

- [ ] **Step 5: Run the full gate**

Run: `uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src tests && uv run pytest`
Expected: all clean. The mypy step is the static half of the acceptance criteria
(`assert_type` calls in `tests/test_proto_seed.py`).

- [ ] **Step 6: Commit**

```bash
git add src/remora/proto/__init__.py tests/test_proto_seed.py
git commit -m "core: re-export seed protocols and add issue #13 acceptance tests"
```

---

## Verification against acceptance criteria

- `IP.src`/`IP.dst` as `FieldRef[IPv4Address]` (class) / `IPv4Address | None` (instance): Task 2 stubs + Task 6 `test_ip_src_class_access_is_field_ref`, `test_ip_instance_access_parses_or_none`.
- `TCP.port` multi-valued (`tuple[int, ...]`): Task 3 table (`multi=1`) + Task 6 `test_tcp_port_is_multi_valued`.
- `.py`/`.pyi` pairing test for all five protocols: Tasks 1–5, `TestStubTablePairing` parametrized over `SEEDS`.
- `TCP.port == 443` builds an `Expr`; `pkt[TCP].srcport` types as `int | None` under `mypy --strict`: Task 6 `test_tcp_port_comparison_builds_expr`, `check_packet_protocol_typing`.
- Stubs pass `mypy --strict`; modules follow the frozen compact-table format: every task's full-gate step (`mypy --strict src tests` covers the stubs because the test file imports and exercises them).
