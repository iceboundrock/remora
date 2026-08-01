# Remora

A type-safe, IDE-friendly Python DSL for Wireshark/tshark capture analysis. Remora drives tshark subprocesses directly (no pyshark dependency): field access is statically typed, display filters are built from real expressions instead of bare strings, and predicates are pushed down to tshark where possible.

> A full README with quickstart and install instructions is tracked in [#24](https://github.com/iceboundrock/remora/issues/24).

## Roadmap

Each milestone has an EPIC issue defining its execution path and the PR ↔ issue plan:

| Milestone | EPIC | Goal |
|-----------|------|------|
| M1 可用内核 | [#40](https://github.com/iceboundrock/remora/issues/40) | end-to-end typed query over a pcap |
| M2 生成器与分发 | [#41](https://github.com/iceboundrock/remora/issues/41) | codegen + fingerprint + distribution |
| M3 打磨 | [#42](https://github.com/iceboundrock/remora/issues/42) | extended operators, real-tshark validation, docs |
| M4 数据工作区 | [#43](https://github.com/iceboundrock/remora/issues/43) | DuckDB materialized workspace |

### M1 可用内核 — dependency graph

Goal: run one end-to-end typed query against a pcap. Arrows point from a blocker to the issue it unblocks.

```mermaid
graph TD
    I1["#1 chore: bootstrap skeleton + CI"]
    I2["#2 core: Expr expression tree"]
    I3["#3 core: typed value conversion"]
    I4["#4 reader: tshark subprocess lifecycle"]
    I6["#6 core: compile Expr → display filter"]
    I7["#7 core: compile Expr → Python predicate"]
    I8["#8 core: Field / FieldRef descriptor"]
    I9["#9 reader: -T fields projection reader"]
    I10["#10 reader: -T ek fallback reader"]
    I11["#11 core: lazy protocol metaclass"]
    I12["#12 core: query planner (two-level pushdown)"]
    I13["#13 core: seed protocols (eth/ip/tcp/udp/dns)"]
    I15["#15 core: end-to-end Capture API"]
    I20["#20 test: pcap fixtures + e2e tests"]

    I2 --> I6
    I2 --> I7
    I2 --> I8
    I4 --> I9
    I4 --> I10
    I8 --> I11
    I6 --> I12
    I7 --> I12
    I3 --> I13
    I11 --> I13
    I9 --> I15
    I10 --> I15
    I12 --> I15
    I13 --> I15
    I15 --> I20
```

Milestones: [M1 可用内核](https://github.com/iceboundrock/remora/milestone/1) · [M2 生成器与分发](https://github.com/iceboundrock/remora/milestone/2) · [M3 打磨](https://github.com/iceboundrock/remora/milestone/3)
