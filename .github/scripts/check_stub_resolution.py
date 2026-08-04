"""Extras stub resolution: mypy must resolve remora.proto.wlan from the wheel.

`assert_type` is the load-bearing assertion. Without the shipped `wlan.pyi`,
`ProtocolMeta.__getattr__` types `WLAN.fc_type` as `Any`, and a plain
`ref: FieldRef[int] = WLAN_DIRECT.fc_type` annotation would still typecheck --
only an exact-type assertion tells "stub resolved" apart from "fell back to Any".

Run under `mypy --strict --python-version 3.12`: this repo's pyproject pins mypy
to python_version 3.10, where `typing.assert_type` does not exist, and
typing_extensions is not a dependency of the built wheels.
"""

from typing import assert_type

# `remora.proto.wlan` ships in the remora-wireless wheel, not in this repo's
# src/ tree, so ruff's isort sorts it into the third-party block.
from remora.proto.wlan import WLAN as WLAN_DIRECT

from remora.expr import Expr
from remora.fields import FieldRef

assert_type(WLAN_DIRECT.fc_type, FieldRef[int])

expr: Expr = WLAN_DIRECT.fc_type == 1
