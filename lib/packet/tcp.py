# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import struct

from . import packet_base
from . import packet_utils


class tcp(packet_base.PacketBase):
    """TCP (RFC 793) header encoder/decoder class.

    An instance has the following attributes at least.
    Most of them are same to the on-wire counterparts but in host byte order.
    __init__ takes the correspondig args in this order.

    ============== ====================
    Attribute      Description
    ============== ====================
    src_port       Source Port
    dst_port       Destination Port
    seq            Sequence Number
    ack            Acknowledgement Number
    offset         Data Offset
    bits           Control Bits
    window_size    Window
    csum           Checksum \
                   (0 means automatically-calculate when encoding)
    urgent         Urgent Pointer
    option         An bytearray containing Options and following Padding. \
                   None if no options.
    ============== ====================
    """

    _PACK_STR = '!HHIIBBHHH'
    _MIN_LEN = struct.calcsize(_PACK_STR)

    _STR_CONVERT_RULE = {'bits': lambda value: format(value, '09b'),
                         'csum': lambda value: '0x%x' % value}

    def __init__(self, src_port, dst_port, seq, ack, offset,
                 bits, window_size, csum, urgent, option=None):
        super(tcp, self).__init__()
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq = seq
        self.ack = ack
        self.offset = offset
        self.bits = bits
        self.window_size = window_size
        self.csum = csum
        self.urgent = urgent
        self.option = option

    def __len__(self):
        return self.offset * 4

    @classmethod
    def parser(cls, buf):
        (src_port, dst_port, seq, ack, offset, bits, window_size,
         csum, urgent) = struct.unpack_from(cls._PACK_STR, buf)
        offset = offset >> 4
        bits = bits & 0x3f
        length = offset * 4
        if length > tcp._MIN_LEN:
            option = buf[tcp._MIN_LEN:length]
        else:
            option = None
        msg = cls(src_port, dst_port, seq, ack, offset, bits,
                  window_size, csum, urgent, option)

        return msg, None, buf[length:]

    def serialize(self, payload, prev):
        length = len(self)
        h = bytearray(length)
        offset = self.offset << 4
        struct.pack_into(tcp._PACK_STR, h, 0, self.src_port, self.dst_port,
                         self.seq, self.ack, offset, self.bits,
                         self.window_size, self.csum, self.urgent)

        if self.option:
            assert (length - tcp._MIN_LEN) >= len(self.option)
            h[tcp._MIN_LEN:tcp._MIN_LEN + len(self.option)] = self.option

        if self.csum == 0:
            total_length = length + len(payload)
            self.csum = packet_utils.checksum_ip(prev, total_length,
                                                 h + payload)
            struct.pack_into('!H', h, 16, self.csum)
        return h
