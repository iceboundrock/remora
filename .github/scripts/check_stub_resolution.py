"""Extras stub resolution: mypy must resolve `remora.proto.<module>` from every extra.

`assert_type` is the load-bearing assertion. Without the shipped `wlan.pyi`,
`ProtocolMeta.__getattr__` types `WLAN.fc_type` as `Any`, and a plain
`ref: FieldRef[int] = WLAN_DIRECT.fc_type` annotation would still typecheck --
only an exact-type assertion tells "stub resolved" apart from "fell back to Any".

Resolving a stub needs two things, and this file is checked in the two layouts
that differ in the second:

* the `.pyi` itself, which each extras distribution ships beside its `.py`;
* a `py.typed` marker in the `remora/` directory the module was found in
  (PEP 561), which each extras distribution ships as `remora/py.typed` (#77).

In a **wheel** install every distribution unpacks into one
`site-packages/remora/`, so core's marker already covered the extras and the
per-distribution ones are redundant. In an **editable or multi-root** layout
each distribution keeps its own `remora/` root, mypy finds `remora.proto.wlan`
under the extra's root, and without a marker *there* it reports
`Skipping analyzing "remora.proto.wlan": module is installed, but missing
library stubs or py.typed marker` and types the field as `Any`. CI therefore
runs this file in both layouts -- the `checks` job in this repo's editable uv
workspace, the `wheels` job in a venv built from the wheels.

One module per extras distribution, so a marker missing from any single
distribution fails here rather than riding on its siblings'.

Run under `mypy --strict --python-version 3.12`: this repo's pyproject pins mypy
to python_version 3.10, where `typing.assert_type` does not exist, and
typing_extensions is not a dependency of the built wheels. `--python-version`
only selects typeshed semantics, so the interpreter mypy itself runs on may be
any version the CI matrix uses.
"""

from typing import assert_type

# These modules ship in the remora-{wireless,industrial,telecom} distributions,
# not in this repo's src/ tree, so ruff's isort sorts them into the third-party
# block.
from remora.proto.gtp import GTP as GTP_DIRECT
from remora.proto.modbus import MODBUS as MODBUS_DIRECT
from remora.proto.wlan import WLAN as WLAN_DIRECT

from remora.expr import Expr
from remora.fields import FieldRef

assert_type(WLAN_DIRECT.fc_type, FieldRef[int])
assert_type(MODBUS_DIRECT.func_code, FieldRef[int])
assert_type(GTP_DIRECT.flags, FieldRef[int])

expr: Expr = WLAN_DIRECT.fc_type == 1
