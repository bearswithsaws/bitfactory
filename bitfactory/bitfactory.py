"""BitFactory package
"""

import abc
import binascii
import logging
import struct
from collections import OrderedDict
from enum import Enum

from .exceptions import BFEndianException, BFRangeException, BFTypeException


class BFEndian(Enum):
    """BFEndian

    Args:
        Enum (int): Endian
    """

    LITTLE = 1
    BIG = 2


class BFBasicDataType(abc.ABC):
    """BFBasicDataType

    Abstract base class for all data types
    """

    def __init__(self):
        pass

    @property
    def value(self):
        pass

    @value.setter
    def value(self, value):
        pass

    @abc.abstractmethod
    def pack(self):
        pass

    @property
    def length(self):
        pass


class BFUInt8(BFBasicDataType):
    """Unsigned int 8-bit"""

    def __init__(self, value=0):
        self._fmt = "B"
        self._width = 1
        self.value = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, val):
        if isinstance(val, int):
            self._value = val & 0xFF
        elif isinstance(val, bytes):
            if len(val) > 1:
                raise BFRangeException
            self._value = ord(val)
        else:
            raise BFTypeException

    def pack(self):
        return struct.pack(self._fmt, self._value)

    @property
    def length(self):
        return self._width

    def __str__(self):
        return self.pretty_print()

    def pretty_print(self, indent=0):
        return " " * indent + "|- " + f"Unsigned Byte 0x{self.value:02X}"


class BFSInt8(BFUInt8):
    """Signed int 8-bit"""

    def __init__(self, **kwargs):
        self._fmt = "b"
        super().__init__(**kwargs)

    def pretty_print(self, indent=0):
        return " " * indent + "|- " + f"Signed Byte 0x{self.value:02X}"


class BFUInt16(BFBasicDataType):
    """Unsigned int 16-bit"""

    def __init__(self, value=0, endian=BFEndian.LITTLE):
        if endian == BFEndian.LITTLE:
            self._endian = "<"
        elif endian == BFEndian.BIG:
            self._endian = ">"
        else:
            raise BFEndianException
        self._fmt = "H"
        self._width = 2
        self.value = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, val):
        if isinstance(val, int):
            self._value = val & 0xFFFF
        else:
            if len(val) > 2:
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
        return " " * indent + "|- " + f"Unsigned Short 0x{self.value:04X}"


class BFSInt16(BFUInt16):
    """docstring for BFSInt16"""

    def __init__(self, **kwargs):
        self._fmt = "h"
        super().__init__(**kwargs)

    def pretty_print(self, indent=0):
        return " " * indent + "|- " + f"Signed Short 0x{self.value:04X}"


class BFUInt32(BFBasicDataType):
    """Unsigned int 32-bit"""

    def __init__(self, value=0, endian=BFEndian.LITTLE):
        if endian == BFEndian.LITTLE:
            self._endian = "<"
        elif endian == BFEndian.BIG:
            self._endian = ">"
        else:
            raise BFEndianException
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


class BFSInt32(BFUInt32):
    """docstring for BFSInt32"""

    def __init__(self, **kwargs):
        self._fmt = "i"
        super().__init__(**kwargs)

    def pretty_print(self, indent=0):
        return " " * indent + "|- " + f"Signed Long 0x{self.value:08X}"


class BFBuffer(BFBasicDataType):
    """Buffer data type"""

    def __init__(self, value=b""):
        self._value = value
        self._width = len(self._value)

    @property
    def length(self):
        return self._width

    def pack(self):
        return self.value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, val):
        if isinstance(val, bytes):
            self._value = val
        else:
            raise BFTypeException("BFBuffer must be type: bytes")

    def pretty_print(self, indent=0):
        short_val = str(binascii.hexlify(self.pack()))
        if self.length > 10:
            short_val = str(binascii.hexlify(self.pack()[:10])) + "..."
        return " " * indent + "|- " + f"Buffer {short_val}"


# is a container a basic data type or its own thing?
class BFContainer(BFBasicDataType):
    """docstring for BFContainer"""

    def __init__(self):
        self._children = OrderedDict()
        self._name = None
        self._parent = None

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def parent(self):
        return self._parent

    @parent.setter
    def parent(self, parent):
        self._parent = parent

    def add(self, name, obj):
        root = name
        obj._parent = self
        sub_container = None
        logging.debug(name)
        if "." in root:
            root, sub_container = root.split(".", 1)
        logging.debug("%s : %s", root, sub_container)
        logging.debug("Adding %s to %s (sub: %s)", type(obj), root, sub_container)
        if root is not None and sub_container is None and isinstance(obj, BFContainer):
            logging.debug("SETTING NAME!!! %s", sub_container)
            obj.name = root
        if root in iter(self._children) and sub_container is not None:
            # Recurse
            logging.debug("%s in children for this container", root)
            self._children[root].add(sub_container, obj)
        else:
            logging.debug("New child, Setting %s to %s", root, obj)
            self._children[root] = obj

        return self

    def __getattribute__(self, name):
        if name != "_children" and name in self._children.keys():
            return self._children[name]

        return super().__getattribute__(name)

    def __setattr__(self, name, obj):
        if isinstance(obj, BFBasicDataType) and not name.startswith(
            "_"
        ):  # Or whatever a container is?
            logging.debug("SETTER: %s", name)
            self.add(name, obj)
        else:
            super().__setattr__(name, obj)

    @property
    def length(self):
        return len(repr(self))

    # Does value make sense? Does this show we need another basic class type?
    # @property
    # def value(self, value):
    #     pass

    def _get_children(self):
        """Returns a copy of its children"""
        return list(iter(self._children.values()))[:]

    def pack(self):
        data = b""
        children = self._get_children()
        while len(children):
            child = children.pop()
            if isinstance(child, BFBasicDataType):
                data = child.pack() + data
            else:
                data = repr(child) + data
        return data

    # def __str__( self ):
    #    return binascii.hexlify( repr( self ) )

    def __str__(self):
        return self.pretty_print()

    def pretty_print(self, indent=0):
        ret = " " * indent + f"+{self.name}\n"
        for child in self._children:
            logging.debug("current child: %s (%s)", child, indent)
            if isinstance(self._children[child], BFContainer):
                ret += "|" + self._children[child].pretty_print(indent + 1)
            else:
                ret += (
                    "|"
                    + self._children[child].pretty_print(indent + 1)
                    + f" : {child} "
                    + "\n"
                )
        return ret


class BFLength(BFContainer):
    """Length counted container"""

    def __init__(self, field, container):
        super().__init__()
        self._field = field
        self._children["_data"] = container

    def __getattribute__(self, name):
        if name != "_children" and name in self._children["_data"]._children.keys():
            return self._children["_data"]._children[name]

        return super(BFContainer, self).__getattribute__(name)

    def __setattr__(self, name, obj):
        if isinstance(obj, BFBasicDataType) and not name.startswith("_"):
            self.add("_data." + name, obj)
        else:
            super(BFContainer, self).__setattr__(name, obj)

    def pack(self):
        data = b""
        children = self._get_children()
        while len(children):
            child = children.pop()
            if isinstance(child, BFBasicDataType):
                data = child.pack() + data
            else:
                data = repr(child) + data

        self._field.value = len(data)
        return self._field.pack() + data

    @property
    def value(self):
        data = b""
        children = self._get_children()
        while len(children):
            child = children.pop()
            if isinstance(child, BFBasicDataType):
                data = child.pack() + data
            else:
                data = repr(child) + data
        self._field.value = len(data)
        return self._field.value

    def __str__(self):
        return self.pretty_print()

    def pretty_print(self, indent=0):
        ret = " " * indent + f"+{self.name} length: 0x{self.value:0x}\n"
        for child in self._children["_data"]._children:
            logging.debug("current child: %s (%s)", child, indent)
            if isinstance(self._children["_data"]._children[child], BFContainer):
                ret += "|" + self._children["_data"]._children[child].pretty_print(
                    indent + 1
                )
            else:
                ret += (
                    "|"
                    + self._children["_data"]._children[child].pretty_print(indent + 1)
                    + f" : {child} "
                    + "\n"
                )
        return ret


class BFLengthRef(BFContainer):
    """Length counted container, referencing another part of the tree"""

    def __init__(self, field, container_ref):
        super().__init__()
        self._field = field
        self._ref = container_ref
        # self._children["_data"] = container_ref

    def _get_root(self, obj) -> BFBasicDataType:
        if obj.parent is None:
            return obj
        return self._get_root(obj.parent)

    def _get_children(self):
        """Returns the length someones children"""
        root = self._get_root(self)
        # a.b.c -> a, b, c
        obj = root
        path_parts = self._ref.split(".")
        for part in path_parts:
            obj = obj._children[part]

        return obj

    def pack(self):
        children = self._get_children()
        self._field.value = len(children.pack())
        return self._field.pack()

    @property
    def value(self):
        children = self._get_children()
        self._field.value = len(children.pack())
        return self._field.value

    def __str__(self):
        return self.pretty_print()

    def pretty_print(self, indent=0):
        ret = " " * indent + f"+{self.name} length: 0x{self.value:0x}\n"

        return ret


class BFCallableRef(BFContainer):
    """Compute a field based on a reference to a branch and a callable"""

    def __init__(self, field, func, container_ref):
        super().__init__()
        self._field = field
        self._func = func
        self._ref = container_ref

    def _get_root(self, obj) -> BFBasicDataType:
        if obj.parent is None:
            return obj
        return self._get_root(obj.parent)

    def _get_children(self):
        """Returns children of the branch referred to"""
        root = self._get_root(self)
        # a.b.c -> a, b, c
        obj = root
        path_parts = self._ref.split(".")
        for part in path_parts:
            obj = obj._children[part]

        return obj

    def pack(self):
        children = self._get_children()
        self._field.value = self._func(children.pack())
        return self._field.pack()

    @property
    def value(self):
        children = self._get_children()
        self._field.value = self._func(children.pack())
        return self._field.value

    def __str__(self):
        return self.pretty_print()

    def pretty_print(self, indent=0):
        ret = " " * indent + f"+{self.name} value: 0x{self.value:0x}\n"

        return ret


def main():
    pass


if __name__ == "__main__":
    main()
