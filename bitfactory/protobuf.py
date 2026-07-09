"""Google Protocol Buffers wire types for BitFactory (extension layer).

This module is an **optional extension** — importing :mod:`bitfactory` does not
pull it in. Bring it into scope explicitly::

    from bitfactory.protobuf import BFProtoMessage, BFVarint, BFProtoString

Importing the module runs the ``@register_type`` decorators below, so after the
import the types are also reachable through the registry
(``get_type("proto_varint")``, ``types_with_tag("varint")``). When the package
is installed, the entry points declared in ``pyproject.toml`` under the
``bitfactory.types`` group let :func:`bitfactory.load_plugins` discover these
types automatically — the "pip install a new protocol layer" experience the
registry was designed for.

It doubles as an advanced tutorial for three parts of the BitFactory redesign:

* **The registry** — every type here is a plain class decorated with
  ``@register_type``; nothing in the core changes to support them.
* **Computed fields** — a length-delimited protobuf field carries a varint
  length prefix. That prefix is a :func:`bitfactory.length_of` computed field
  over the payload, so it recomputes at pack time and, being ``mutable`` by
  default, lets fuzzers inject length/data mismatches for free.
* **Trait-tag mutator dispatch** — :class:`BFVarint` packs completely
  differently from a fixed-width integer, yet by advertising the ``"integer"``
  trait it is fuzzed by the *existing* integer mutator suite with no new code.

Scope
-----
BitFactory is a serializer/fuzzer: it *builds* bytes, it does not parse them.
This module therefore implements protobuf **encoding**. The bytes it produces
are valid on the wire, so any conformant protobuf decoder can read them (given
the field numbers/types, which live out-of-band in a ``.proto`` schema exactly
as they do for real protobuf).

Wire format recap
------------------
A message is a flat sequence of fields. Each field is a *key* varint followed by
a payload. The key encodes ``(field_number << 3) | wire_type``:

===== ========= ====================================== ============================
Wire  Name      Payload                                Protobuf types
===== ========= ====================================== ============================
0     VARINT    base-128 varint                        int32/64, uint32/64, bool,
                                                       enum, sint (zigzag)
1     I64       8 bytes, little-endian                  fixed64, sfixed64, double
2     LEN       varint length prefix + raw bytes        string, bytes, embedded
                                                       message, packed repeated
5     I32       4 bytes, little-endian                  fixed32, sfixed32, float
===== ========= ====================================== ============================
"""

from __future__ import annotations

import struct

from .bitfactory import (
    BFBasicDataType,
    BFComputed,
    BFContainer,
    length_of,
)
from .exceptions import BFRangeException, BFTypeException
from .registry import register_type

# Wire type constants (see module docstring).
WIRE_VARINT = 0
WIRE_I64 = 1
WIRE_LEN = 2
WIRE_I32 = 5

_WIRE_NAMES = {
    WIRE_VARINT: "VARINT",
    WIRE_I64: "I64",
    WIRE_LEN: "LEN",
    WIRE_I32: "I32",
}

_U64_MASK = (1 << 64) - 1


def encode_varint(value: int) -> bytes:
    """Encode a non-negative integer as a base-128 (LEB128) varint.

    Seven bits are emitted per byte, least-significant group first; every byte
    except the last has its high bit set to signal "more to come".
    """
    if value < 0:
        raise BFRangeException("encode_varint requires a non-negative integer")
    out = bytearray()
    while True:
        group = value & 0x7F
        value >>= 7
        if value:
            out.append(group | 0x80)
        else:
            out.append(group)
            return bytes(out)


def zigzag_encode(value: int, bits: int) -> int:
    """ZigZag-map a signed integer so small magnitudes stay small varints.

    ``0 -> 0, -1 -> 1, 1 -> 2, -2 -> 3, ...`` — used by protobuf's ``sint32`` /
    ``sint64`` so that negative numbers do not become 10-byte varints.
    """
    return (value << 1) ^ (value >> (bits - 1))


# =============================================================================
# Varint family (wire type 0)
# =============================================================================


@register_type("proto_varint")
class BFVarint(BFBasicDataType):
    """Unsigned base-128 varint (protobuf wire type 0).

    Backs ``uint32``, ``uint64``, ``bool`` and ``enum``. The stored value is an
    unsigned integer masked to ``bit_width`` (default 64), and :meth:`pack`
    emits the varint byte sequence.

    Although it packs nothing like a fixed-width field, it advertises the
    ``"integer"`` trait (plus ``bit_width`` / ``signed``), so every integer
    mutator — boundary, sign, special-value, bit-pattern — applies to it
    automatically. That is the whole point of trait-based dispatch: a brand-new
    packing scheme reuses the existing fuzzing suite for free.
    """

    #: This field's protobuf wire type; read by :class:`BFProtoField`.
    WIRE_TYPE = WIRE_VARINT
    #: Trait tags added on top of the shared integer/scalar tags.
    EXTRA_TAGS: frozenset = frozenset({"varint"})
    #: Nominal width in bits; bounds the stored value and mutator boundaries.
    BIT_WIDTH = 64
    #: Whether this varint carries a signed logical value (see subclasses).
    SIGNED = False

    def __init__(self, value: int = 0):
        self._mask = (1 << self.BIT_WIDTH) - 1
        self.value = value

    @property
    def bit_width(self) -> int:
        return self.BIT_WIDTH

    @property
    def signed(self) -> bool:
        return self.SIGNED

    @property
    def tags(self) -> frozenset:
        base = {
            "integer",
            "scalar",
            "signed" if self.SIGNED else "unsigned",
            f"width:{self.bit_width}",
        }
        return frozenset(base) | self.EXTRA_TAGS

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, val) -> None:
        if isinstance(val, bool):
            # bool is an int subclass; store it as 0/1 without surprises.
            self._value = int(val)
        elif isinstance(val, int):
            # Mask like a fixed-width integer so mutator overflow values wrap
            # consistently (max+1 -> 0) instead of growing the varint forever.
            self._value = val & self._mask
        elif isinstance(val, (bytes, bytearray)):
            self._value = int.from_bytes(bytes(val), "little") & self._mask
        else:
            raise BFTypeException(f"{type(self).__name__} value must be int or bytes")

    @property
    def length(self) -> int:
        return len(self.pack())

    def _wire_value(self) -> int:
        """The unsigned integer actually encoded (overridden by signed types)."""
        return self._value

    def pack(self) -> bytes:
        return encode_varint(self._wire_value())

    def __str__(self) -> str:
        return self.pretty_print()

    def pretty_print(self, indent: int = 0) -> str:
        return " " * indent + "|- " + f"Varint {self.value} (0x{self.value & _U64_MASK:x})"


@register_type("proto_signed_varint")
class BFSignedVarint(BFVarint):
    """Two's-complement 64-bit varint (protobuf ``int32`` / ``int64``).

    Protobuf encodes a negative ``int32``/``int64`` as its unsigned 64-bit
    two's-complement value, which is always a 10-byte varint. Positive values
    encode identically to :class:`BFVarint`. The signed value is preserved for
    display and mutation; only the wire representation is unsigned.
    """

    EXTRA_TAGS = frozenset({"varint", "signed-varint"})
    SIGNED = True

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, val) -> None:
        if isinstance(val, bool):
            self._value = int(val)
        elif isinstance(val, int):
            # Keep the signed value as-is; two's complement happens at pack time.
            self._value = val
        elif isinstance(val, (bytes, bytearray)):
            self._value = int.from_bytes(bytes(val), "little")
        else:
            raise BFTypeException(f"{type(self).__name__} value must be int or bytes")

    def _wire_value(self) -> int:
        return self._value & _U64_MASK


@register_type("proto_zigzag_varint")
class BFZigZagVarint(BFVarint):
    """ZigZag-encoded 64-bit varint (protobuf ``sint32`` / ``sint64``).

    Negative values stay compact: ``-1`` is one byte, not ten. The signed value
    is preserved for display and mutation; :meth:`_wire_value` applies the
    ZigZag transform before varint encoding.
    """

    EXTRA_TAGS = frozenset({"varint", "zigzag"})
    SIGNED = True

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, val) -> None:
        if isinstance(val, bool):
            self._value = int(val)
        elif isinstance(val, int):
            self._value = val
        elif isinstance(val, (bytes, bytearray)):
            self._value = int.from_bytes(bytes(val), "little")
        else:
            raise BFTypeException(f"{type(self).__name__} value must be int or bytes")

    def _wire_value(self) -> int:
        return zigzag_encode(self._value, 64) & _U64_MASK


# =============================================================================
# Fixed-width IEEE-754 floats (wire types 5 and 1)
# =============================================================================


@register_type("proto_float")
class BFProtoFloat(BFBasicDataType):
    """32-bit IEEE-754 float, little-endian (protobuf ``float``, wire type 5).

    Fixed 32-bit *integers* (``fixed32``/``sfixed32``) are just little-endian
    ``BFUInt32``/``BFSInt32`` and need no new type; pair them with an explicit
    ``wire_type=WIRE_I32`` when wrapping in a :class:`BFProtoField`.
    """

    WIRE_TYPE = WIRE_I32
    TAGS = frozenset({"float", "fixed32", "scalar"})
    BYTE_WIDTH = 4
    _STRUCT = "<f"

    def __init__(self, value: float = 0.0):
        self.value = value

    @property
    def value(self) -> float:
        return self._value

    @value.setter
    def value(self, val) -> None:
        if isinstance(val, bool):
            raise BFTypeException(f"{type(self).__name__} value must be a number or bytes")
        if isinstance(val, (int, float)):
            self._value = float(val)
        elif isinstance(val, (bytes, bytearray)):
            if len(val) != self.BYTE_WIDTH:
                raise BFRangeException(
                    f"{type(self).__name__} needs exactly {self.BYTE_WIDTH} bytes, got {len(val)}"
                )
            self._value = struct.unpack(self._STRUCT, bytes(val))[0]
        else:
            raise BFTypeException(f"{type(self).__name__} value must be a number or bytes")

    @property
    def length(self) -> int:
        return self.BYTE_WIDTH

    def pack(self) -> bytes:
        return struct.pack(self._STRUCT, self._value)

    def __str__(self) -> str:
        return self.pretty_print()

    def pretty_print(self, indent: int = 0) -> str:
        return " " * indent + "|- " + f"Float{self.BYTE_WIDTH * 8} {self._value!r}"


@register_type("proto_double")
class BFProtoDouble(BFProtoFloat):
    """64-bit IEEE-754 double, little-endian (protobuf ``double``, wire type 1)."""

    WIRE_TYPE = WIRE_I64
    TAGS = frozenset({"float", "fixed64", "scalar"})
    BYTE_WIDTH = 8
    _STRUCT = "<d"


# =============================================================================
# Length-delimited payload (wire type 2)
# =============================================================================


@register_type("proto_string")
class BFProtoString(BFBasicDataType):
    """UTF-8 text payload (protobuf ``string``, wire type 2).

    :meth:`pack` returns only the raw UTF-8 content. The length prefix that
    frames a length-delimited field is added by :class:`BFProtoField` (as a
    computed :func:`bitfactory.length_of` varint), so the framing lives in one
    place and stays fuzzable. Raw ``bytes`` fields reuse the core
    :class:`bitfactory.BFBuffer` (detected via its ``"bytes"`` tag).
    """

    WIRE_TYPE = WIRE_LEN
    TAGS = frozenset({"len", "string", "bytes"})

    def __init__(self, value: str = ""):
        self.value = value

    @property
    def value(self) -> str:
        return self._value

    @value.setter
    def value(self, val) -> None:
        if isinstance(val, str):
            self._value = val
        elif isinstance(val, (bytes, bytearray)):
            self._value = bytes(val).decode("utf-8")
        else:
            raise BFTypeException(f"{type(self).__name__} value must be str or bytes")

    @property
    def length(self) -> int:
        return len(self.pack())

    def pack(self) -> bytes:
        return self._value.encode("utf-8")

    def __str__(self) -> str:
        return self.pretty_print()

    def pretty_print(self, indent: int = 0) -> str:
        shown = self._value if len(self._value) <= 30 else self._value[:30] + "..."
        return " " * indent + "|- " + f"String {shown!r}"


# =============================================================================
# Structural types: the tag/value field and the message container
# =============================================================================


def _resolve_wire_type(value: BFBasicDataType, explicit: int | None) -> int:
    """Determine the protobuf wire type for ``value``.

    An explicit override wins; otherwise a ``WIRE_TYPE`` class attribute is
    used; otherwise the value's trait tags decide (length-delimited payloads —
    strings, byte buffers, embedded messages — map to ``LEN``).
    """
    if explicit is not None:
        if explicit not in _WIRE_NAMES:
            raise BFTypeException(f"unknown wire type {explicit!r}")
        return explicit
    wt = getattr(type(value), "WIRE_TYPE", None)
    if wt is not None:
        return int(wt)
    if {"len", "string", "bytes", "buffer", "container", "message"} & value.tags:
        return WIRE_LEN
    raise BFTypeException(
        f"cannot infer a protobuf wire type for {type(value).__name__}; pass wire_type= explicitly"
    )


@register_type("proto_key")
class BFProtoKey(BFVarint):
    """The tag key of a protobuf field: ``varint((field_number << 3) | wire)``.

    A key is *structural* — mutating it changes which field/type a decoder
    thinks it is reading, not the field's data. So it deliberately drops the
    ``"integer"``/``"scalar"`` traits: value-fuzzing mutators skip it and the
    tag stays well-formed, while the field's payload is still fuzzed normally.
    (Drop this type into a structure directly if you *want* to fuzz tags.)
    """

    EXTRA_TAGS = frozenset({"varint", "proto-key"})

    @property
    def tags(self) -> frozenset:
        return frozenset({"varint", "proto-key", "unsigned", f"width:{self.bit_width}"})


@register_type("proto_field")
class BFProtoField(BFContainer):
    """A single protobuf field: a tag key followed by a payload.

    ``BFProtoField(field_number, value)`` infers the wire type from ``value``
    (see :func:`_resolve_wire_type`) or takes an explicit ``wire_type``. It is a
    container whose children pack in order:

    * ``_key`` — a structural :class:`BFProtoKey` varint.
    * ``_len`` — for ``LEN`` payloads only, a mutable
      :func:`bitfactory.length_of` varint over the value (so a fuzzer can inject
      a length that disagrees with the data).
    * ``_value`` — the payload field.
    """

    TAGS = frozenset({"container", "proto-field"})

    def __init__(self, field_number: int, value: BFBasicDataType, wire_type: int | None = None):
        super().__init__()
        if not isinstance(value, BFBasicDataType):
            raise BFTypeException("value must be a BitFactory type")
        if not isinstance(field_number, int) or isinstance(field_number, bool):
            raise BFTypeException("field_number must be an int")
        if not 1 <= field_number <= (1 << 29) - 1:
            raise BFRangeException("protobuf field numbers range from 1 to 2**29 - 1")

        wt = _resolve_wire_type(value, wire_type)
        self._field_number = field_number
        self._wire_type = wt

        key = BFProtoKey((field_number << 3) | wt)
        key._parent = self
        self._children["_key"] = key

        value._parent = self
        if wt == WIRE_LEN:
            # Mutable computed length prefix over the payload (length/data
            # mismatch is a whole bug class for length-delimited formats).
            length_field: BFComputed = length_of(BFVarint(), value)
            length_field._parent = self
            self._children["_len"] = length_field
        self._children["_value"] = value

    @property
    def field_number(self) -> int:
        return self._field_number

    @property
    def wire_type(self) -> int:
        return self._wire_type

    def pretty_print(self, indent: int = 0) -> str:
        wire = _WIRE_NAMES.get(self._wire_type, str(self._wire_type))
        ret = " " * indent + f"+field {self._field_number} ({wire})\n"
        for name, child in self._children.items():
            if isinstance(child, BFContainer):
                ret += "|" + child.pretty_print(indent + 1)
            else:
                ret += "|" + child.pretty_print(indent + 1) + f" : {name} \n"
        return ret


@register_type("proto_message")
class BFProtoMessage(BFContainer):
    """A protobuf message: an ordered collection of :class:`BFProtoField`.

    Used at the top level it packs to the message body. Passed as the ``value``
    of another :class:`BFProtoField` it becomes a length-delimited embedded
    message (wire type ``LEN``), which is why it advertises ``WIRE_TYPE``.
    """

    WIRE_TYPE = WIRE_LEN
    TAGS = frozenset({"container", "message", "len"})

    def add_field(
        self, field_number: int, value: BFBasicDataType, wire_type: int | None = None
    ) -> BFProtoMessage:
        """Append a field and return ``self`` for chaining.

        Repeated fields (same number more than once) are allowed; each gets a
        unique child name so both survive in the packed output.
        """
        field = BFProtoField(field_number, value, wire_type)
        name = f"field{field_number}"
        suffix = 1
        while name in self._children:
            name = f"field{field_number}_{suffix}"
            suffix += 1
        self.add(name, field)
        return self
