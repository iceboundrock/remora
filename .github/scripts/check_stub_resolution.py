"""Extras stub resolution: mypy must resolve remora.proto.wlan from the wheel."""

# `remora.proto.wlan` ships in the remora-wireless wheel, not in this repo's
# src/ tree, so ruff's isort sorts it into the third-party block.
from remora.proto.wlan import WLAN as WLAN_DIRECT

from remora.expr import Expr
from remora.fields import FieldRef

ref: FieldRef[int] = WLAN_DIRECT.fc_type
expr: Expr = WLAN_DIRECT.fc_type == 1
