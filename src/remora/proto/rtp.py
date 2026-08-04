# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

"""Generated protocol module for tshark layer ``rtp`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["RTP"]


class RTP(ProtocolBase):
    """Real-Time Transport Protocol (tshark layer ``rtp``)."""

    _proto_ = "rtp"
    _table_: ClassVar[FieldTable] = {
        "ext_rfc5285_appbits": ("rtp.ext.rfc5285.appbits", "FT_UINT8", 0),
        "block_length": ("rtp.block-length", "FT_UINT16", 0),
        "csrc_item": ("rtp.csrc.item", "FT_UINT32", 0),
        "fragment_overlap_conflict": ("rtp.fragment.overlap.conflict", "FT_BOOLEAN", 0),
        "csrc_items": ("rtp.csrc.items", "FT_NONE", 0),
        "cc": ("rtp.cc", "FT_UINT8", 0),
        "ext_profile": ("rtp.ext.profile", "FT_UINT16", 0),
        "fragment_error": ("rtp.fragment.error", "FT_FRAMENUM", 0),
        "extseq": ("rtp.extseq", "FT_UINT32", 0),
        "timestamp_ext": ("rtp.timestamp_ext", "FT_UINT64", 0),
        "ext": ("rtp.ext", "FT_BOOLEAN", 0),
        "ext_rfc5285_data": ("rtp.ext.rfc5285.data", "FT_BYTES", 0),
        "ext_len": ("rtp.ext.len", "FT_UINT16", 0),
        "follow": ("rtp.follow", "FT_BOOLEAN", 0),
        "fragment_count": ("rtp.fragment.count", "FT_UINT32", 0),
        "fragment_overlap": ("rtp.fragment.overlap", "FT_BOOLEAN", 0),
        "fragment_toolongfragment": ("rtp.fragment.toolongfragment", "FT_BOOLEAN", 0),
        "padding_bogus": ("rtp.padding_bogus", "FT_NONE", 0),
        "padding_missing": ("rtp.padding_missing", "FT_NONE", 0),
        "hdr_ext": ("rtp.hdr_ext", "FT_UINT32", 0),
        "hdr_exts": ("rtp.hdr_exts", "FT_NONE", 0),
        "ext_rfc5285_id": ("rtp.ext.rfc5285.id", "FT_UINT8", 0),
        "ext_rfc5285_len": ("rtp.ext.rfc5285.len", "FT_UINT8", 0),
        "marker": ("rtp.marker", "FT_BOOLEAN", 0),
        "fragment_multipletails": ("rtp.fragment.multipletails", "FT_BOOLEAN", 0),
        "padding": ("rtp.padding", "FT_BOOLEAN", 0),
        "padding_count": ("rtp.padding.count", "FT_UINT8", 0),
        "padding_data": ("rtp.padding.data", "FT_BYTES", 0),
        "payload": ("rtp.payload", "FT_BYTES", 0),
        "p_type": ("rtp.p_type", "FT_UINT8", 0),
        "rfc4571_len": ("rtp.rfc4571.len", "FT_UINT16", 0),
        "fragment": ("rtp.fragment", "FT_FRAMENUM", 0),
        "fragments": ("rtp.fragments", "FT_NONE", 0),
        "reassembled_in": ("rtp.reassembled_in", "FT_FRAMENUM", 0),
        "fragment_unfinished": ("rtp.fragment_unfinished", "FT_NONE", 0),
        "reassembled_length": ("rtp.reassembled.length", "FT_UINT32", 0),
        "srtp_auth_tag": ("srtp.auth_tag", "FT_BYTES", 0),
        "srtp_enc_payload": ("srtp.enc_payload", "FT_BYTES", 0),
        "srtp_mki": ("srtp.mki", "FT_BYTES", 0),
        "seq": ("rtp.seq", "FT_UINT16", 0),
        "setup_method": ("rtp.setup-method", "FT_STRING", 0),
        "setup_frame": ("rtp.setup-frame", "FT_FRAMENUM", 0),
        "setup": ("rtp.setup", "FT_STRING", 0),
        "ssrc": ("rtp.ssrc", "FT_UINT32", 0),
        "timestamp": ("rtp.timestamp", "FT_UINT32", 0),
        "timestamp_offset": ("rtp.timestamp-offset", "FT_UINT16", 0),
        "version": ("rtp.version", "FT_UINT8", 0),
    }
