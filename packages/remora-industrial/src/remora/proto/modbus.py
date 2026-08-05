# remora-fingerprint: v1
# tshark: 4.6.6
# dump-sha256: 630382087156e14bd89d187b03f348d56b4e3b966b05d17d41fc2ec9c09f008e
# env: plugins=sha256:54f0935767ee
# generator: remora 0.1.0

"""Generated protocol module for tshark layer ``modbus`` — do not edit."""

from typing import ClassVar

from remora.proto._meta import FieldTable, ProtocolBase

__all__ = ["MODBUS"]


class MODBUS(ProtocolBase):
    """Modbus (tshark layer ``modbus``)."""

    _proto_ = "modbus"
    _table_: ClassVar[FieldTable] = {
        "and_mask": ("modbus.and_mask", "FT_UINT16", 0),
        "bit_cnt": ("modbus.bit_cnt", "FT_UINT16", 0),
        "bitnum": ("modbus.bitnum", "FT_UINT16", 0),
        "bitval": ("modbus.bitval", "FT_BOOLEAN", 0),
        "ev_recv_broadcast": ("modbus.ev_recv_broadcast", "FT_UINT8", 0),
        "byte_cnt": ("modbus.byte_cnt", "FT_UINT8", 0),
        "byte_cnt_16": ("modbus.byte_cnt_16", "FT_UINT16", 0),
        "diagnostic_ascii_input_delimiter": ("modbus.diagnostic.ascii_input_delimiter", "FT_UINT8", 0),
        "diagnostic_bus_comm_error_count": ("modbus.diagnostic.bus_comm_error_count", "FT_UINT16", 0),
        "ev_recv_char_over": ("modbus.ev_recv_char_over", "FT_UINT8", 0),
        "diagnostic_clear_ctr_diag_reg": ("modbus.diagnostic.clear_ctr_diag_reg", "FT_UINT16", 0),
        "ev_recv_comm_err": ("modbus.ev_recv_comm_err", "FT_UINT8", 0),
        "conformity_level": ("modbus.conformity_level", "FT_UINT8", 0),
        "ev_recv_lo_mode": ("modbus.ev_recv_lo_mode", "FT_UINT8", 0),
        "ev_send_lo_mode": ("modbus.ev_send_lo_mode", "FT_UINT8", 0),
        "data": ("modbus.data", "FT_BYTES", 0),
        "diagnostic_code": ("modbus.diagnostic_code", "FT_UINT16", 0),
        "diagnostic_return_diag_register": ("modbus.diagnostic.return_diag_register", "FT_UINT16", 0),
        "diagnostic_return_query_data_echo": ("modbus.diagnostic.return_query_data.echo", "FT_BYTES", 0),
        "event": ("modbus.event", "FT_UINT8", 0),
        "ev_count": ("modbus.ev_count", "FT_UINT16", 0),
        "exception": ("modbus.exception", "FT_BOOLEAN", 0),
        "exception_code": ("modbus.exception_code", "FT_UINT8", 0),
        "diagnostic_bus_exception_error_count": ("modbus.diagnostic.bus_exception_error_count", "FT_UINT16", 0),
        "func_code": ("modbus.func_code", "FT_UINT8", 0),
        "data_decode": ("modbus.data.decode", "FT_NONE", 0),
        "mei": ("modbus.mei", "FT_UINT8", 0),
        "ev_msg_count": ("modbus.ev_msg_count", "FT_UINT16", 0),
        "more_follows": ("modbus.more_follows", "FT_UINT8", 0),
        "next_object_id": ("modbus.next_object_id", "FT_UINT8", 0),
        "num_objects": ("modbus.num_objects", "FT_UINT8", 0),
        "or_mask": ("modbus.or_mask", "FT_UINT16", 0),
        "object_id": ("modbus.object_id", "FT_UINT8", 0),
        "object_str_value": ("modbus.object_str_value", "FT_STRING", 0),
        "object_value": ("modbus.object_value", "FT_BYTES", 0),
        "objects_len": ("modbus.objects_len", "FT_UINT8", 0),
        "padding": ("modbus.padding", "FT_UINT8", 0),
        "read_device_id": ("modbus.read_device_id", "FT_UINT8", 0),
        "ev_send_read_ex": ("modbus.ev_send_read_ex", "FT_UINT8", 0),
        "read_reference_num": ("modbus.read_reference_num", "FT_UINT16", 0),
        "read_word_cnt": ("modbus.read_word_cnt", "FT_UINT16", 0),
        "reference_num": ("modbus.reference_num", "FT_UINT16", 0),
        "reference_num_32": ("modbus.reference_num_32", "FT_UINT32", 0),
        "reference_type": ("modbus.reference_type", "FT_UINT8", 0),
        "regnum16": ("modbus.regnum16", "FT_UINT16", 0),
        "regnum32": ("modbus.regnum32", "FT_UINT32", 0),
        "regval_float": ("modbus.regval_float", "FT_FLOAT", 0),
        "regval_int16": ("modbus.regval_int16", "FT_INT16", 0),
        "regval_int32": ("modbus.regval_int32", "FT_INT32", 0),
        "regval_uint16": ("modbus.regval_uint16", "FT_UINT16", 0),
        "regval_uint32": ("modbus.regval_uint32", "FT_UINT32", 0),
        "diagnostic_return_query_data_request": ("modbus.diagnostic.return_query_data.request", "FT_BYTES", 0),
        "request_frame": ("modbus.request_frame", "FT_FRAMENUM", 0),
        "diagnostic_restart_communication_option": ("modbus.diagnostic.restart_communication_option", "FT_UINT16", 0),
        "ev_send_slave_abort_ex": ("modbus.ev_send_slave_abort_ex", "FT_UINT8", 0),
        "ev_send_slave_busy_ex": ("modbus.ev_send_slave_busy_ex", "FT_UINT8", 0),
        "diagnostic_bus_char_overrun_count": ("modbus.diagnostic.bus_char_overrun_count", "FT_UINT16", 0),
        "diagnostic_slave_busy_count": ("modbus.diagnostic.slave_busy_count", "FT_UINT16", 0),
        "diagnostic_slave_message_count": ("modbus.diagnostic.slave_message_count", "FT_UINT16", 0),
        "diagnostic_slave_nak_count": ("modbus.diagnostic.slave_nak_count", "FT_UINT16", 0),
        "diagnostic_no_slave_response_count": ("modbus.diagnostic.no_slave_response_count", "FT_UINT16", 0),
        "ev_send_slave_nak_ex": ("modbus.ev_send_slave_nak_ex", "FT_UINT8", 0),
        "ev_status": ("modbus.ev_status", "FT_UINT16", 0),
        "response_time": ("modbus.response_time", "FT_RELATIVE_TIME", 0),
        "diagnostic_bus_message_count": ("modbus.diagnostic.bus_message_count", "FT_UINT16", 0),
        "word_cnt": ("modbus.word_cnt", "FT_UINT16", 0),
        "write_reference_num": ("modbus.write_reference_num", "FT_UINT16", 0),
        "ev_send_write_timeout": ("modbus.ev_send_write_timeout", "FT_UINT8", 0),
        "write_word_cnt": ("modbus.write_word_cnt", "FT_UINT16", 0),
    }
