# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

"""Generated protocol module for tshark layer ``pop`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["POP"]


class POP(ProtocolBase):
    """Post Office Protocol (tshark layer ``pop``)."""

    _proto_ = "pop"
    _table_: ClassVar[FieldTable] = {
        "response": ("pop.response", "FT_STRING", 0),
        "response_indicator": ("pop.response.indicator", "FT_STRING", 0),
        "response_description": ("pop.response.description", "FT_STRING", 0),
        "response_data": ("pop.response.data", "FT_STRING", 0),
        "request": ("pop.request", "FT_STRING", 0),
        "request_command": ("pop.request.command", "FT_STRING", 0),
        "request_parameter": ("pop.request.parameter", "FT_STRING", 0),
        "request_data": ("pop.request.data", "FT_STRING", 0),
        "data_fragments": ("pop.data.fragments", "FT_NONE", 0),
        "data_fragment": ("pop.data.fragment", "FT_FRAMENUM", 0),
        "data_fragment_overlap": ("pop.data.fragment.overlap", "FT_BOOLEAN", 0),
        "data_fragment_overlap_conflicts": ("pop.data.fragment.overlap.conflicts", "FT_BOOLEAN", 0),
        "data_fragment_multiple_tails": ("pop.data.fragment.multiple_tails", "FT_BOOLEAN", 0),
        "data_fragment_too_long_fragment": ("pop.data.fragment.too_long_fragment", "FT_BOOLEAN", 0),
        "data_fragment_error": ("pop.data.fragment.error", "FT_FRAMENUM", 0),
        "data_fragment_count": ("pop.data.fragment.count", "FT_UINT32", 0),
        "data_reassembled_in": ("pop.data.reassembled.in", "FT_FRAMENUM", 0),
        "data_reassembled_length": ("pop.data.reassembled.length", "FT_UINT32", 0),
        "response_tot_len_invalid": ("pop.response.tot_len.invalid", "FT_NONE", 0),
    }
