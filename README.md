# Remora

A type-safe Python DSL for analyzing Wireshark/tshark capture files.

Remora gives Python developers typed protocol fields and composable queries
instead of hand-written display-filter strings and dynamic field access. It
drives tshark directly, pushes supported filters down to it, and can optionally
cache selected fields in a DuckDB workspace for repeated analysis. It does not
depend on pyshark.

## Why Remora?

Compared with a string-based pyshark query:

```python
cap = pyshark.FileCapture("capture.pcap", display_filter="ip.src == 10.0.0.1 && tcp.port == 443")
src = pkt["ip"].src  # dynamic field access
```

Remora builds a query from typed fields and returns parsed Python values:

<!-- ci:exec -->
```python
from remora import IP, TCP, Capture

cap = Capture("capture.pcap").filter((IP.src == "10.0.0.1") & (TCP.port == 443))
```

Generated stubs provide IDE completion and types such as `IPv4Address | None`
for `pkt[IP].src`. Queries are lazy: iteration starts tshark, and Remora cleans
up the subprocess when iteration finishes or the iterator is closed. Projections
limit the fields read, and a workspace lets you query materialized columns
without re-dissecting the capture each time.

## Quick start

### Prerequisites

- Python 3.10 or later. CI tests Python 3.10–3.14 on Linux and Python 3.12 on Windows.
- [tshark](https://www.wireshark.org/download.html) installed and on `PATH`.
  Alternatively, set `TSHARK` or pass `tshark="/path/to/tshark"` to `Capture`.
  For example, Debian/Ubuntu users can install the `tshark` package.

### Installation

Install from the public GitHub repository:

```sh
python -m pip install "remora @ git+https://github.com/iceboundrock/remora.git"
```

This project is pre-1.0. **Do not install `remora` by name from PyPI**: that
name belongs to an unrelated project. See [protocol extensions](#protocol-extensions)
and [workspace](#duckdb-workspace) for optional dependencies.

### Your first query

Place a pcap named `capture.pcap` in your working directory, or replace the path
below with your own capture. To try the exact example, download the repository's
[sample capture](tests/data/sample.pcap) and save it as `capture.pcap`.

<!-- ci:run -->
```python
from remora import IP, TCP, Capture

cap = Capture("capture.pcap")

for pkt in cap.filter((IP.src == "10.0.0.1") & (TCP.port == 443)):
    print(pkt[IP].src, pkt[TCP].dstport)
```

The loop prints the source IP and TCP destination port of each matching packet.
The sample includes a matching packet; your own capture may produce different results or no
output. This example is typechecked and run against a real tshark in CI.

## Usage

### Typed fields

Accessing a field on a protocol class, such as `IP.src`, creates a field
reference for expressions. Accessing it on a packet view, `pkt[IP].src`, returns
the parsed value. Scalar fields return a value or `None` when absent;
multi-value fields return a tuple, or `()` when absent. For example,
`pkt[TCP].port` is a `tuple[int, ...]`.

Core protocols are available from `remora.proto`; `ETH`, `IP`, `TCP`, `UDP`
and `DNS` are also exported from `remora`:

<!-- ci:exec -->
```python
from remora import IP, Capture
from remora.proto import HTTP, QUIC, TLS

query = (IP.src == "10.0.0.1") & (HTTP.request_method == "GET")
handshake = QUIC.long_packet_type.present() | TLS.handshake_type.present()
cap = Capture("capture.pcap").filter(query)
```

### Filtering

Combine expressions with `&`, `|`, and `~`, and parenthesize comparisons.
Do not use `and`, `or`, `not`, or chained comparisons: they require a Python
truth value, and an expression raises `TypeError` when truth-tested.

<!-- ci:exec -->
```python
from remora import IP, TCP

good = (IP.src == "10.0.0.1") & (TCP.port == 443)
alternative = (IP.src == "10.0.0.1") | (IP.dst == "10.0.0.1")
negated = ~(TCP.port == 443)
```

A comparison on a multi-value field matches when **any occurrence** matches.
`TCP.port != 80` means **no occurrence** equals 80: it is `~(TCP.port == 80)`,
not Wireshark's “any occurrence differs” interpretation. It also matches
packets where `tcp.port` is absent; add `TCP.port.present()` if absence should
not match.

<!-- ci:exec -->
```python
from remora import TCP

not_port_80 = TCP.port != 80
present_and_not_80 = TCP.port.present() & (TCP.port != 80)
```

Fields also support `in_()`, `contains()`, `matches()`, and `present()`.
See the [semantics guide](docs/semantics.md) for absence, regex portability,
and backend restrictions.

### Projection and query planning

Use `select()` to name the fields your code reads. The planner normally uses
`-T fields` for a projection rather than the whole-packet `-T ek` reader:

<!-- ci:exec -->
```python
from remora import IP, TCP, Capture

cap = Capture("capture.pcap").filter(TCP.port == 443).select(IP.src, TCP.dstport)

assert cap.plan().mode == "fields"
```

In fields mode, reading a field outside the projection raises
`FieldNotProjectedError`. A projected field that is absent still returns `None`
or `()`.
The planner adds fields needed by residual expressions automatically.

Supported conjuncts are pushed to tshark as a display filter; other expressions
are evaluated as Python residuals when supported there. An opaque Python
callable passed to `filter()` runs in Python and forces whole-packet `-T ek`
mode, even with `select()`. Other pushable conjuncts can still be pushed down.
Inspect `cap.plan().explain()` to see the plan. Invalid literals and unsupported
operations can raise rather than silently approximate.

**Reader limits:** with tshark older than 4.4, control characters in
`-T fields` values can remain escaped and affect residual results. On any
version, a field value containing byte `0x1e` can be split into multiple
occurrences in fields mode. Use whole-packet `-T ek` when those values matter.
Workspace materialization also uses `-T fields`; see the
[reader limitations](docs/semantics.md#what-is-still-divergent) before caching
such data.

## DuckDB workspace

`Capture` re-dissects the pcap on each iteration. For repeated queries over the
same capture, a workspace materializes selected fields in DuckDB and evaluates
expressions as SQL over those columns. Install the optional dependency from a
checkout (the brackets must be quoted):

```sh
git clone https://github.com/iceboundrock/remora.git
python -m pip install './remora[workspace]'
```

With `capture.pcap` in the working directory:

<!-- ci:run -->
```python
from remora import IP, TCP
from remora.workspace import Workspace

with Workspace("capture.duckdb", mode="rw") as ws:
    ws.materialize("capture.pcap", [IP.src, IP.dst, TCP.port])

with Workspace("capture.duckdb") as ws:  # read-only is the default
    for row in ws.query().filter(TCP.port == 443).select(IP.src):
        print(row.frame_number, row.get(IP.src))
    ws.export_parquet("pkts", "pkts.parquet")
```

The workspace caches only the fields you materialize, so keep the original pcap
to revisit other fields or raw bytes. Queries require the fields they use to be
materialized. The SQL backend refuses some expressions that `Capture` supports,
and materialization filters must be fully pushable to tshark. See the [workspace guide](docs/workspace.md) for reuse,
locking, exports, streams, annotations, and cross-capture analysis.

DuckDB is optional. PyArrow is a separate optional dependency needed for
`Query.arrow()`, not for the Parquet export above; install both with
`python -m pip install './remora[workspace,arrow]'` from the checkout's parent.

## Protocol extensions

In addition to the core protocols listed in [codegen.toml](codegen.toml), three
separate distributions add domain-specific fields:

| Distribution | Protocols |
| --- | --- |
| `remora-wireless` | `WLAN`, `RADIOTAP` |
| `remora-industrial` | `MODBUS`, `MBTCP`, `DNP3` |
| `remora-telecom` | `GTP`, `DIAMETER` |

These distributions are not currently published on PyPI. Install the ones you
need from a checkout, alongside core; for example:

```sh
git clone https://github.com/iceboundrock/remora.git
python -m pip install ./remora ./remora/packages/remora-wireless
```

Replace the package path with `remora-industrial` or `remora-telecom`, or list
multiple package paths. Although `pyproject.toml` defines `wireless`,
`industrial`, `telecom`, and `all` extras, their protocol distributions cannot
currently be resolved from PyPI. `all` also includes DuckDB and PyArrow.

The dynamic import below works at runtime when the distribution is installed,
but a type checker sees `object`:

<!-- ci:exec -->
```python
from remora.proto import WLAN
```

For static typing and IDE completion, import from the generated submodule:

```python
from remora.proto.wlan import WLAN
```

### Local generation (`psdsl gen`)

For a protocol missing from the shipped sets, including one provided by a local
dissector or plugin, generate modules against your installed tshark:

```sh
psdsl gen --protocols mqtt --out ./gen
```

The generated `.py` and `.pyi` files can be imported as `gen.mqtt` when the
parent of `gen` is on Python's import path and Remora is installed. Fields are
scalar unless listed with `--multi`, and a repeated field left scalar returns
only its first occurrence. See the [codegen guide](docs/codegen.md#worked-example-generating-a-non-core-protocol-with-psdsl-gen)
for a complete example and multiplicity configuration.

## Documentation

- [Semantics](docs/semantics.md): absence, expression behavior, regex and reader limits.
- [Workspace](docs/workspace.md): materialization, cache reuse, locking, exports and analysis.
- [Code generation](docs/codegen.md): local generation, regeneration and drift checks.

## Development and contributing

Clone the repository and install the development environment with
[uv](https://docs.astral.sh/uv/):

```sh
git clone https://github.com/iceboundrock/remora.git
cd remora
uv sync
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict src tests
uv run mypy --strict --python-version 3.12 .github/scripts/check_stub_resolution.py
```

Some tests require a real tshark; use `uv run pytest -m "not integration"` to
run without integration tests. Report problems or propose changes through
[GitHub Issues](https://github.com/iceboundrock/remora/issues) and pull requests.
For repository conventions, see [AGENTS.md](AGENTS.md).

Protocol modules are generated, not hand-edited. See the
[regeneration instructions](docs/codegen.md#checking-and-regenerating) for the
pinned tshark toolchain and drift-check procedure.

## Roadmap

The milestone epics record their scope and remaining work:

- Completed: [M1 typed capture queries (#40)](https://github.com/iceboundrock/remora/issues/40),
  [M2 generation and distribution (#41)](https://github.com/iceboundrock/remora/issues/41),
  and [M3 operators, validation and docs (#42)](https://github.com/iceboundrock/remora/issues/42).
- In progress: [M4 DuckDB workspace (#43)](https://github.com/iceboundrock/remora/issues/43).
  The workspace features shown above are already implemented; the epic tracks
  outstanding work.

## License and support

Remora is distributed under the [MIT License](LICENSE). For questions and bug
reports, use [GitHub Issues](https://github.com/iceboundrock/remora/issues).
