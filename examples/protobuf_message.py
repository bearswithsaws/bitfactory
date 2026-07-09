#!/usr/bin/env python3
"""Google Protocol Buffers as a BitFactory extension.

Builds a protobuf message out of the extension types in ``bitfactory.protobuf``,
prints the field tree and the packed wire bytes, checks them against a
hand-computed expectation, and then shows the *existing* mutator suite fuzzing
the new types with no protobuf-specific mutator code.

This demonstrates three redesign features at once:

* registry-based custom types (``@register_type`` in bitfactory/protobuf.py),
* computed length prefixes (``length_of`` powers the LEN framing, and is
  mutable so length/data mismatches are generated automatically), and
* trait-tag mutator dispatch (varints advertise the ``"integer"`` trait, so the
  integer mutators fuzz them despite the base-128 packing).

Run:
    python examples/protobuf_message.py
"""

from bitfactory import BFMutatable, create_full_mutator_suite
from bitfactory.protobuf import (
    BFProtoDouble,
    BFProtoMessage,
    BFProtoString,
    BFSignedVarint,
    BFVarint,
    BFZigZagVarint,
)


def build_person() -> BFProtoMessage:
    """A message roughly like the canonical protobuf ``Person`` example.

    .proto equivalent::

        message Person {
          int64  id      = 1;   // signed varint
          string name    = 2;   // length-delimited
          sint32 balance = 3;   // zigzag varint
          double height  = 4;   // fixed 64-bit
          Person friend  = 5;   // embedded message
        }
    """
    person = BFProtoMessage()
    person.add_field(1, BFSignedVarint(1000))
    person.add_field(2, BFProtoString("Ada Lovelace"))
    person.add_field(3, BFZigZagVarint(-42))
    person.add_field(4, BFProtoDouble(1.72))

    friend = BFProtoMessage()
    friend.add_field(1, BFVarint(2))
    friend.add_field(2, BFProtoString("Grace"))
    person.add_field(5, friend)  # nested message -> length-delimited (LEN)
    return person


def main() -> None:
    person = build_person()

    print("Field tree:")
    print(person)

    packed = person.pack()
    print("Packed wire bytes:", packed.hex())

    # Cross-check the first two fields against the hand-computed wire encoding.
    #   field 1: key 0x08, signed varint 1000 -> e8 07
    #   field 2: key 0x12, len 0x0c, "Ada Lovelace"
    expected_prefix = "08" + "e807" + "12" + "0c" + b"Ada Lovelace".hex()
    assert packed.hex().startswith(expected_prefix), packed.hex()
    print("Wire-format check: OK\n")

    # The full mutator suite fuzzes the new types with zero protobuf-specific
    # mutator code: value varints (integer traits) and the computed length
    # prefixes (mutable length_of) are both exercised.
    mutatable = BFMutatable(person)
    for mutator in create_full_mutator_suite():
        mutatable.add_mutator(mutator)

    print(f"Auto-generated {mutatable.total_count()} mutations. First 8:")
    for result in mutatable:
        if result.index >= 8:
            break
        print(f"  [{result.index}] {result.path}: {result.description}")

    fuzzed_paths = sorted({r.path for r in mutatable})
    print("\nDistinct fuzzed field paths:")
    for path in fuzzed_paths:
        print(f"  - {path}")


if __name__ == "__main__":
    main()
