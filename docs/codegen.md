# Codegen: regenerating protocol modules

Everything under `src/remora/proto/` except `_meta.py` and `__init__.py` — and every `remora/proto/` module inside the `packages/remora-*` extras distributions — is a **generated artifact**. Each generated `.py`/`.pyi` pair opens with a five-line fingerprint header:

```text
# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: <sha256 of the canonicalized `tshark -G fields` dump>
# env: plugins=sha256:<12 hex of the `tshark -G plugins` name/version/type columns>
# generator: remora <version>
```

(`_extras.py`, the module → extra map that `remora.proto.__init__` consumes, is generated too.) CI's `codegen-drift` job re-runs the generator on every pull request and every push to `main` and diffs the result against the committed bytes, so hand-editing a generated file always fails CI.

The single source of truth for the toolchain is **`codegen.toml`** at the repo root:

- `[tshark] version` — the pinned tshark (tracks what `ppa:wireshark-dev/stable` ships for `ubuntu-latest`). The pin appears nowhere else; CI and the docs defer to it.
- `[generate] protocols` — the committed core protocol set; `multi` — the hand-curated multi-value field abbrevs (`-G fields` carries no multiplicity signal).
- `[extras.<name>] protocols` — protocols shipped by the separate `remora-<name>` distributions under `packages/` (`wireless`, `industrial`, `telecom` are the only accepted names). A protocol may be assigned to core *or* to one extra, never both.

## Checking and regenerating

```sh
uv run python -m remora.codegen check   # diff committed artifacts vs a fresh regeneration
uv run python -m remora.codegen write   # regenerate in place (core + extras packages)
```

Both commands start by comparing the tshark they resolve against `[tshark] version` and **exit 2 without touching anything** if it differs:

```text
error: installed tshark 4.6.7 does not match the pinned 4.6.6 in codegen.toml;
install the pinned version or update the pin and regenerate every artifact
```

That is the expected outcome on a developer machine — your Wireshark is almost never the pinned build. Do not chase a matching local install; use the Docker recipe below.

Past the pin check, `check` exits 1 and prints a unified diff per drifted file (plus a line for any missing file, and for any *orphan* — a fingerprinted file still on disk that the current `codegen.toml` no longer generates). `write` overwrites every destination and exits 0 — except that a protocol abbrev in `codegen.toml` that the dump does not contain fails both commands loudly with exit 2 rather than being skipped. Both accept `--config`, `--proto-dir`, `--packages-dir`, and `--tshark` if you need to point them somewhere else; the defaults assume you run from the repository root.

Regeneration is **architecture-neutral** (issue #97): run it natively on whatever your host is. Two things make it so. The canonicalized `-G fields` dump is the same text on either architecture under one pinned tshark — a native arm64 run of the pinned 4.6.6 reproduces the `dump-sha256` of the committed artifacts, which CI's amd64 `codegen-drift` job independently keeps green. And the `env:` line hashes only the `(name, version, type)` columns of each `-G plugins` record — never the fourth, path column, which embeds the multiarch triplet (`/usr/lib/x86_64-linux-gnu/...` vs `aarch64-linux-gnu`) and used to confine reproduction to amd64 by itself. The PPA publishes the same tshark revision for both architectures, so the pin is reachable either way.

`.github/workflows/codegen-arch-verify.yml` is what measures this directly: a matrix `probe` job running natively on GitHub-managed `ubuntu-latest` (x86_64) and `ubuntu-24.04-arm` (aarch64), plus a `compare` job that diffs the two results so the verdict is the job status. Only the two matrix legs run `.github/scripts/codegen_arch_probe.py` — each on its own architecture, uploading its report as an artifact; `compare` runs no tshark and no probe of its own, it downloads both reports and fails unless their `tshark`, `dump-sha256` and `env` lines are identical (`machine:` is expected to differ). The probe reads the pin from `codegen.toml` and **exits 2 rather than probing** if the installed tshark is not that version — evidence collected under an unpinned toolchain would compare two builds that were never the same.

It has two triggers. `workflow_dispatch` runs it on demand, against any ref. A paths-filtered `pull_request` trigger runs it automatically on pull requests that touch what the architecture claim rests on — `src/remora/codegen/fingerprint.py`, the probe script, `codegen.toml`, or the workflow file — so a change to the fingerprint scheme or the pin re-proves the claim on both architectures before it merges. Every other pull request leaves it idle. It is evidence-gathering, not the guard on committed bytes: `codegen-drift` in `ci.yml` is that.

The trade-off, accepted deliberately: a per-architecture behavioral difference in a same-version plugin no longer flips `env:`. Anything such a difference changes about dissection still changes the `-G fields` dump, so `dump-sha256` catches it — `env:` is the second line of defense.

Run the container natively; do not emulate a foreign architecture, which is slow and proves nothing a native run does not:

```sh
docker run --rm -v "$PWD":/work -w /work ubuntu:24.04 bash -c '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends software-properties-common curl ca-certificates
  add-apt-repository -y ppa:wireshark-dev/stable
  apt-get install -y tshark
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
  export UV_PROJECT_ENVIRONMENT=/tmp/remora-venv
  uv run python -m remora.codegen write
'
```

`UV_PROJECT_ENVIRONMENT` keeps the container's virtualenv out of the mounted checkout — without it `uv run` finds the host's `.venv`, sees an interpreter that does not exist inside the container, and rebuilds it, leaving your host environment broken. On a Linux host the regenerated files also land root-owned (`sudo chown -R "$(id -u):$(id -g)" src packages` afterwards); Docker Desktop on macOS maps ownership for you.

The run takes a minute or two: `tshark -G fields` on a stock 4.6.x build is a ~270k-line dump, and every configured protocol is emitted from it.

Then run the usual gate and commit the regenerated files together with whatever change motivated them:

```sh
uv run ruff check . && uv run ruff format --check . \
  && uv run mypy --strict src tests && uv run pytest
```

## When the CI drift check fails

`codegen-drift` failing means committed bytes ≠ what the pinned toolchain regenerates. Diagnose by what your branch touched:

| You changed | Remediation |
|---|---|
| The emitter (`src/remora/codegen/emit.py`) or the mangle policy (`mangle.py`) | Regenerate everything with `write` (Docker recipe above); commit the regenerated tree in the same PR. Both files are frozen contracts — changing them rewrites every artifact, so expect a large diff. |
| `codegen.toml`: added a protocol, curated a `multi` entry, moved a protocol between core and an extra | Same: regenerate with `write` and commit. A protocol moved between destinations leaves the old file behind — `git rm` it, or `check` reports it as an orphan. |
| `codegen.toml`: removed a protocol | `write` does not delete anything. Delete the stale `.py`/`.pyi` pair by hand, then re-run `check` until the orphan report is empty. |
| `[tshark] version`, deliberately | Regenerate with `write` under the new pin; pin bump and regenerated artifacts land as one PR, never separately. |
| Nothing — the check broke on `main` | The PPA rolled a new tshark past the pin, so the drift job's tshark no longer matches and `check` exits 2 on the version line. Bump `[tshark] version` to what the PPA now ships, regenerate with `write`, and land the bump plus the regenerated artifacts as one PR. |

If a regenerated file differs only in its `env:` line, your tshark's plugin set differs from the pin's — a different plugin, or a different plugin *version*, since #97 the only things `env:` hashes. The architecture is not it: `env:` no longer sees the plugin paths.

## Worked example: generating a non-core protocol with `psdsl gen`

The committed set covers everyday protocols; anything else — including plugin and Lua dissectors only *your* tshark knows — is generated locally with `psdsl gen`. It runs the same dump → parse → emit → fingerprint pipeline, but against whatever tshark is installed, with **no version pin and no `codegen.toml`**: the fingerprint header simply records what generated the files. MQTT is in neither `[generate] protocols` nor any `[extras.*]`, so it makes a good example:

```sh
uv run psdsl gen --protocols mqtt --out ./gen
```

tshark is resolved from `--tshark`, then `$TSHARK`, then `PATH`, then Homebrew. The command writes `gen/mqtt.py` and its `gen/mqtt.pyi` stub, and reports what it did:

```text
wrote gen/mqtt.py
wrote gen/mqtt.pyi
wrote 2 artifact(s) under tshark 4.6.7
```

Real dumps contain a handful of malformed or duplicated records, so `warning: -G fields line <n>: ...` lines on stderr are normal and do not affect the emitted protocol. Failures are loud and one line long, with exit code 2 — `error: protocol 'nosuchproto' not found in the -G fields dump`, or `error: tshark not found at ...`.

**Curate multiplicity.** `-G fields` carries no multiplicity signal, so the multi-value set is supplied by hand. One TCP segment can carry several MQTT control messages, and tshark dissects each of them, so `mqtt.topic` and `mqtt.msg` genuinely occur more than once in a packet. Declare them:

```sh
uv run psdsl gen --protocols mqtt --multi mqtt.topic mqtt.msg --out ./gen
```

Fields listed in `--multi` become `MultiField` attributes; everything else stays scalar and resolves to its first occurrence. The difference is visible in the stub — and note the fence tag: `.pyi` examples must be marked ```` ```pyi ````, because ruff formats ```` ```python ```` fences in Markdown as `.py` source and would reject stub syntax.

```pyi
class MQTT(ProtocolBase):
    topic: MultiField[str]  # tuple[str, ...] on instance access
    msg: MultiField[bytes]
    msgid: Field[int]  # int | None on instance access
```

Attribute names come from the frozen mangle policy, not from the abbrev verbatim: the protocol prefix is stripped and every non-alphanumeric character becomes `_`, so `mqtt.topic` → `topic`, `mqtt.property.content_type` → `property_content_type`, `mqtt.clientid_len` → `clientid_len`. A name that would start with a digit gets an `f_` prefix, one that would start with `_` gets an `f` prefix, and a Python keyword gets a trailing `_`. Always check the emitted `.pyi` for the name you want rather than guessing — the mapping is not reversible, and `--multi` takes the **tshark abbrev** (`mqtt.topic`), never the attribute name.

**Import the output.** The parent of `gen/` must be on the import path — automatic when `gen/` sits in your project root and you run Python from there — and `remora` must be installed in the importing environment. No `__init__.py` is needed:

```python
from gen.mqtt import MQTT

from remora import Capture

for pkt in Capture("broker.pcap").filter(MQTT.topic == "sensors/temp"):
    print(pkt[MQTT].topic)  # tuple[str, ...] — mqtt.topic was declared multi
```

`MQTT.topic == "sensors/temp"` compiles to the display filter `mqtt.topic == "sensors/temp"` and is pushed down to tshark exactly like a shipped protocol; the any-occurrence semantics of multi-value fields apply unchanged.

Locally generated modules are yours to keep — they are not committed to this repository, and `uv run python -m remora.codegen check` ignores them (it only looks at the destinations `codegen.toml` names). If a protocol deserves to ship, add it to `[generate] protocols` (or an `[extras.*]` set), regenerate under the pin, and commit the artifacts.

For the user-facing version of this section — output layout, `mypy_path` for out-of-tree output — see the [README's Local generation section](../README.md#local-generation-psdsl-gen).
