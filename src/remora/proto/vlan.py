# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
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
        "cfi": ("vlan.cfi", "FT_BOOLEAN", 0),
        "dei": ("vlan.dei", "FT_BOOLEAN", 0),
        "id": ("vlan.id", "FT_UINT16", 0),
        "len": ("vlan.len", "FT_UINT16", 0),
        "len_past_end": ("vlan.len.past_end", "FT_NONE", 0),
        "id_name": ("vlan.id_name", "FT_STRING", 0),
        "priority": ("vlan.priority", "FT_UINT16", 0),
        "too_many_tags": ("vlan.too_many_tags", "FT_NONE", 0),
        "trailer": ("vlan.trailer", "FT_BYTES", 0),
        "etype": ("vlan.etype", "FT_UINT16", 0),
    }
