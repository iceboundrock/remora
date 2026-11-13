# remora-fingerprint: v1
# tshark: 4.6.9
# dump-sha256: cc1997a091bc54fed0977474101bcff6e86a8f39122e1e6da416c24516dab324
# env: plugins=sha256:8654174b828b
# generator: remora 0.1.0

from datetime import timedelta

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase

class UDP(ProtocolBase):
    checksum: Field[int]
    checksum_bad: Field[str]
    checksum_partial: Field[str]
    checksum_status: Field[int]
    checksum_zero: Field[str]
    checksum_calculated: Field[int]
    dstport: Field[int]
    length: Field[int]
    length_bad: Field[str]
    length_bad_zero: Field[str]
    payload: Field[bytes]
    pdu_size: Field[int]
    port: MultiField[int]
    possible_traceroute: Field[str]
    proc_dstcmd: Field[str]
    proc_dstpid: Field[int]
    proc_dstuid: Field[int]
    proc_dstuname: Field[str]
    proc_srccmd: Field[str]
    proc_srcpid: Field[int]
    proc_srcuid: Field[int]
    proc_srcuname: Field[str]
    srcport: Field[int]
    stream: Field[int]
    stream_pnum: Field[int]
    time_delta: Field[timedelta]
    time_relative: Field[timedelta]
    udplite_checksum_coverage_bad: Field[str]
