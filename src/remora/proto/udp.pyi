# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:8654174b828b
# generator: remora 0.1.0

from datetime import timedelta

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase

class UDP(ProtocolBase):
    checksum_bad: Field[str]
    udplite_checksum_coverage_bad: Field[str]
    length_bad: Field[str]
    checksum_calculated: Field[int]
    checksum: Field[int]
    checksum_status: Field[int]
    dstport: Field[int]
    proc_dstpid: Field[int]
    proc_dstcmd: Field[str]
    proc_dstuid: Field[int]
    proc_dstuname: Field[str]
    checksum_zero: Field[str]
    length: Field[int]
    length_bad_zero: Field[str]
    pdu_size: Field[int]
    checksum_partial: Field[str]
    payload: Field[bytes]
    possible_traceroute: Field[str]
    srcport: Field[int]
    port: MultiField[int]
    proc_srcpid: Field[int]
    proc_srccmd: Field[str]
    proc_srcuid: Field[int]
    proc_srcuname: Field[str]
    stream_pnum: Field[int]
    stream: Field[int]
    time_relative: Field[timedelta]
    time_delta: Field[timedelta]
