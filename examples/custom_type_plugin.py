#!/usr/bin/env python3
"""Custom type registration example.

Demonstrates the scapy-style extensibility of BitFactory: you can define new
field types in your own module and register them with a decorator, and they
immediately work with containers, packing, pretty-printing, and — crucially —
the existing mutator suite, with no changes to the library.

Two ways to make a custom type available:

1. In-process (shown here): import this module and the ``@register_type``
   decorators run, registering the types.

2. As an installable plugin: declare entry points in your package metadata so
   ``pip install`` makes the types discoverable automatically::

       [project.entry-points."bitfactory.types"]
       uint24 = "my_pkg.types:BFUInt24"
       macaddr = "my_pkg.types:BFMacAddress"

   ``import bitfactory`` calls ``load_plugins()`` which discovers them.

Run:
    python examples/custom_type_plugin.py
"""

from bitfactory import (
    BFBasicDataType,
    BFContainer,
    BFEndian,
    BFIntegerBoundaryMutator,
    BFIntegerField,
    BFMutatable,
    get_type,
    list_types,
    register_type,
    types_with_tag,
)


# A fixed-width integer of a width BitFactory does not ship: 24 bits. Because
# BFIntegerField derives everything from BYTE_WIDTH/SIGNED, this is all it takes.
@register_type("uint24")
class BFUInt24(BFIntegerField):
    """Unsigned 24-bit integer (common in audio and image formats)."""

    BYTE_WIDTH = 3
    SIGNED = False


# A completely custom, non-integer type: a 6-byte MAC address. It implements the
# minimal field interface (pack + pretty_print + value) and advertises its own
# tags so tooling can discover it.
@register_type("macaddr", tags=frozenset({"address", "bytes"}))
class BFMacAddress(BFBasicDataType):
    """Six-byte MAC address, accepted as ``"aa:bb:cc:dd:ee:ff"`` or bytes."""

    TAGS = frozenset({"address", "bytes"})

    def __init__(self, value="00:00:00:00:00:00"):
        self.value = value

    @property
    def value(self) -> bytes:
        return self._value

    @value.setter
    def value(self, val) -> None:
        if isinstance(val, str):
            val = bytes(int(part, 16) for part in val.split(":"))
        if not isinstance(val, (bytes, bytearray)) or len(val) != 6:
            raise ValueError("MAC address must be 6 bytes")
        self._value = bytes(val)

    @property
    def length(self) -> int:
        return 6

    def pack(self) -> bytes:
        return self._value

    def pretty_print(self, indent: int = 0) -> str:
        pretty = ":".join(f"{b:02x}" for b in self._value)
        return " " * indent + "|- " + f"MAC {pretty}"


def main() -> None:
    print("Registered types:", ", ".join(list_types()))
    print("Integer-tagged types include uint24:", get_type("uint24") in types_with_tag("integer"))
    print()

    # Build a little frame using both a built-in and two custom types.
    frame = BFContainer()
    frame.dst = BFMacAddress("de:ad:be:ef:00:01")
    frame.length = BFUInt24(0x0100, endian=BFEndian.BIG)
    print(frame)
    print("packed:", frame.pack().hex())
    print()

    # The unmodified boundary mutator understands the 24-bit width automatically.
    mutatable = BFMutatable(frame).add_mutator(BFIntegerBoundaryMutator())
    print(f"Auto-generated {mutatable.total_count()} mutations for the uint24 field:")
    for result in mutatable:
        print(f"  [{result.index}] {result.path}: {result.description}")


if __name__ == "__main__":
    main()
