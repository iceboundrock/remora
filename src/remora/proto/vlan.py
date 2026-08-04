# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

"""Generated protocol module for tshark layer ``vlan`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["VLAN"]


class VLAN(ProtocolBase):
    """802.1Q Virtual LAN (tshark layer ``vlan``)."""

    _proto_ = "vlan"
    _table_: ClassVar[FieldTable] = {
        "priority": ("vlan.priority", "FT_UINT16", 0),
        "cfi": ("vlan.cfi", "FT_BOOLEAN", 0),
        "dei": ("vlan.dei", "FT_BOOLEAN", 0),
        "id": ("vlan.id", "FT_UINT16", 0),
        "id_name": ("vlan.id_name", "FT_STRING", 0),
        "etype": ("vlan.etype", "FT_UINT16", 0),
        "len": ("vlan.len", "FT_UINT16", 0),
        "trailer": ("vlan.trailer", "FT_BYTES", 0),
        "len_past_end": ("vlan.len.past_end", "FT_NONE", 0),
        "too_many_tags": ("vlan.too_many_tags", "FT_NONE", 0),
    }
