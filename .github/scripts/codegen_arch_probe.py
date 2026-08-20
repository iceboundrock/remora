"""Print the architecture-sensitive half of a codegen fingerprint (issue #97).

Runs the locally installed tshark and reports the three values that decide
whether regeneration is architecture-neutral:

* the tshark version,
* the sha256 of the *canonicalized* ``-G fields`` dump — the value that lands
  in every artifact's ``dump-sha256`` header line,
* the ``env:`` summary of the ``-G plugins`` dump under the current scheme.

The pinned tshark is **enforced**, not merely reported: the pin is read from
``codegen.toml`` (the repository's single source of truth for it — nothing here
restates a version number) and a mismatch exits 2 without probing, because
evidence gathered under the wrong toolchain would compare two architectures
that were never running the same build.

The dump transforms are imported from ``remora.codegen.fingerprint`` rather
than reimplemented, so a run here and a run inside
``python -m remora.codegen write`` can never disagree. Only the standard
library is needed beyond the checkout itself, so the runners in
``codegen-arch-verify.yml`` need no virtualenv.

Usage: ``python3 .github/scripts/codegen_arch_probe.py [out.txt]``
"""

from __future__ import annotations

import hashlib
import platform
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from remora.codegen.fingerprint import (  # noqa: E402
    canonicalize_dump,
    find_tshark,
    load_config,
    parse_tshark_version,
    summarize_env,
)

CONFIG_PATH = REPO_ROOT / "codegen.toml"


def pin_mismatch_message(found: str, expected: str, config: str) -> str | None:
    """Return None if the installed tshark is the pinned one, else why it is not.

    Kept separate from the probing so the gate is unit-testable without a
    tshark binary; ``main`` refuses to collect evidence whenever this returns
    a message.
    """
    if found == expected:
        return None
    return (
        f"installed tshark {found} does not match the pinned {expected} in {config}; "
        "refusing to record architecture evidence for an unpinned toolchain"
    )


def main(argv: list[str]) -> int:
    expected = load_config(CONFIG_PATH).tshark_version
    tshark = find_tshark()

    def run(*args: str) -> str:
        return subprocess.run([tshark, *args], check=True, capture_output=True, text=True).stdout

    found = parse_tshark_version(run("--version"))
    problem = pin_mismatch_message(found, expected, str(CONFIG_PATH))
    if problem is not None:
        print(f"error: {problem}", file=sys.stderr)
        return 2

    canonical = canonicalize_dump(run("-G", "fields"))
    report = "\n".join(
        [
            f"machine: {platform.machine()}",
            f"tshark: {found}",
            f"pinned: {expected}",
            f"fields-lines: {len(canonical.splitlines())}",
            f"dump-sha256: {hashlib.sha256(canonical.encode('utf-8')).hexdigest()}",
            f"env: {summarize_env(run('-G', 'plugins'))}",
        ]
    )
    print(report)
    if len(argv) > 1:
        Path(argv[1]).write_text(f"{report}\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
