# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 322912d4e14fe37b69f23f55fba883f64cd737f04da4b14a762926dbe6bf1d36
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

from datetime import timedelta

from remora.fields import Field, MultiField
from remora.proto._meta import ProtocolBase

class UDP(ProtocolBase):
    srcport: Field[int]
    dstport: Field[int]
    port: MultiField[int]
    stream: Field[int]
    stream_pnum: Field[int]
    length: Field[int]
    checksum: Field[int]
    checksum_calculated: Field[int]
    checksum_status: Field[int]
    proc_srcuid: Field[int]
    proc_srcpid: Field[int]
    proc_srcuname: Field[str]
    proc_srccmd: Field[str]
    proc_dstuid: Field[int]
    proc_dstpid: Field[int]
    proc_dstuname: Field[str]
    proc_dstcmd: Field[str]
    pdu_size: Field[int]
    time_relative: Field[timedelta]
    time_delta: Field[timedelta]
    payload: Field[bytes]
    possible_traceroute: Field[str]
    length_bad: Field[str]
    udplite_checksum_coverage_bad: Field[str]
    checksum_zero: Field[str]
    checksum_partial: Field[str]
    checksum_bad: Field[str]
    length_bad_zero: Field[str]
