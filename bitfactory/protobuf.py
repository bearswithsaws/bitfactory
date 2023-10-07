"""BitFactory implementation of Google protobuf 
"""

import abc
import binascii
import logging
import struct
from collections import OrderedDict
from enum import Enum

from .bitfactory import BFBasicDataType, BFBuffer, BFContainer, BFEndian, BFLength
from .exceptions import BFEndianException, BFRangeException, BFTypeException


class BFUVarInt128(BFBasicDataType):
    """128 bit varint"""

    def __init__(self, value=0, endian=BFEndian.LITTLE):

        local_int2byte = struct.Struct('>B').pack

        bits = value & 0x7f
        value >>= 7
        while value:
            write(local_int2byte(0x80|bits))
            bits = value & 0x7f
            value >>= 7
        write(local_int2byte(bits))
        self._fmt = "I"
        self._width = 4
        self.value = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, val):
        if isinstance(val, int):
            self._value = val & 0xFFFFFFFF
        else:
            if len(val) > 4:
                raise BFRangeException
            self._value = struct.unpack("@" + self._fmt, val)[0]

    def pack(self):
        return struct.pack(self._endian + self._fmt, self.value)

    @property
    def length(self):
        return self._width

    def __str__(self):
        return self.pretty_print()

    def pretty_print(self, indent=0):
        return " " * indent + "|- " + f"Unsigned Long 0x{self.value:08X}"
