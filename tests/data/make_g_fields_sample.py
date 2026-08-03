"""Regenerate g_fields_sample.txt — a truncated real ``tshark -G fields`` dump.

Usage: uv run python tests/data/make_g_fields_sample.py

Keeps only the records of a fixed protocol set chosen to cover parser and
mangling edge cases:

- eth, ip, tcp, udp, dns — the M1 seed protocols
- 6lowpan  — abbrev starts with a digit; has a ``.class`` keyword field
- acf-can  — hyphen in the abbrev; registers fields not under its prefix (``can.*``)
- iec61883 — digit-leading field segment (``iec61883.4_incorrect_cip_fn``)
- tpkt     — real duplicate P record (appears twice in tshark 4.6.x)

The fixture is checked in and pinned: tests assert exact counts against the
committed file, so regenerating under a different tshark version may require
updating the counts in tests/test_codegen_parse.py (a fingerprint/drift
mechanism is issue #16's scope).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

PROTOCOLS = frozenset({"eth", "ip", "tcp", "udp", "dns", "6lowpan", "acf-can", "iec61883", "tpkt"})
OUT = Path(__file__).parent / "g_fields_sample.txt"


def main() -> None:
    dump = subprocess.run(
        ["tshark", "-G", "fields"], check=True, capture_output=True, text=True
    ).stdout
    kept: list[str] = []
    for line in dump.splitlines():
        columns = line.split("\t")
        is_protocol = columns[0] == "P" and len(columns) == 3 and columns[2] in PROTOCOLS
        is_field = columns[0] == "F" and len(columns) == 8 and columns[4] in PROTOCOLS
        if is_protocol or is_field:
            kept.append(line)
    OUT.write_text("\n".join(kept) + "\n", encoding="utf-8")
    print(f"wrote {len(kept)} records to {OUT}")


if __name__ == "__main__":
    main()
