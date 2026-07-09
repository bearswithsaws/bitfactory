"""Tests for the protobuf extension types (bitfactory/protobuf.py).

Expected bytes are hand-computed from the protobuf wire spec (and cross-checked
against Python's ``google.protobuf`` when it happens to be installed).
"""

import pytest

from bitfactory import (
    BFBuffer,
    BFIntegerBoundaryMutator,
    BFMutatable,
    create_full_mutator_suite,
    get_type,
    list_types,
    types_with_tag,
)
from bitfactory.exceptions import BFRangeException, BFTypeException
from bitfactory.protobuf import (
    WIRE_I32,
    WIRE_LEN,
    WIRE_VARINT,
    BFProtoDouble,
    BFProtoField,
    BFProtoFloat,
    BFProtoKey,
    BFProtoMessage,
    BFProtoString,
    BFSignedVarint,
    BFVarint,
    BFZigZagVarint,
    encode_varint,
    zigzag_encode,
)


class TestVarint:
    @pytest.mark.parametrize(
        "value,expected",
        [
            (0, "00"),
            (1, "01"),
            (127, "7f"),
            (128, "8001"),
            (150, "9601"),
            (300, "ac02"),
            (16384, "808001"),
            ((1 << 64) - 1, "ffffffffffffffffff01"),
        ],
    )
    def test_unsigned_vectors(self, value, expected):
        assert BFVarint(value).pack().hex() == expected
        assert encode_varint(value).hex() == expected

    def test_value_masks_to_width(self):
        # max + 1 wraps to 0, like a fixed-width integer.
        assert BFVarint(1 << 64).pack().hex() == "00"

    def test_bool_stored_as_bit(self):
        assert BFVarint(True).pack().hex() == "01"
        assert BFVarint(False).pack().hex() == "00"

    def test_bytes_input(self):
        assert BFVarint(b"\x96\x01").value == BFVarint(b"\x96\x01").value  # sanity
        assert BFVarint(b"\xff").pack().hex() == "ff01"

    def test_rejects_bad_type(self):
        with pytest.raises(BFTypeException):
            BFVarint("nope")

    def test_encode_varint_negative_rejected(self):
        with pytest.raises(BFRangeException):
            encode_varint(-1)


class TestSignedVarint:
    def test_negative_one_is_ten_bytes(self):
        # int32/int64 -1 encodes as the 64-bit two's complement varint.
        assert BFSignedVarint(-1).pack().hex() == "ffffffffffffffffff01"

    def test_positive_matches_unsigned(self):
        assert BFSignedVarint(300).pack() == BFVarint(300).pack()

    def test_value_preserved_for_display(self):
        assert BFSignedVarint(-5).value == -5

    def test_is_signed_trait(self):
        assert BFSignedVarint(0).signed is True
        assert "signed" in BFSignedVarint(0).tags


class TestZigZag:
    @pytest.mark.parametrize(
        "value,mapped",
        [
            (0, 0),
            (-1, 1),
            (1, 2),
            (-2, 3),
            (2, 4),
            (2147483647, 4294967294),
            (-2147483648, 4294967295),
        ],
    )
    def test_zigzag_encode(self, value, mapped):
        assert zigzag_encode(value, 64) == mapped

    def test_pack_small_negative_is_compact(self):
        assert BFZigZagVarint(-1).pack().hex() == "01"
        assert BFZigZagVarint(1).pack().hex() == "02"

    def test_value_preserved(self):
        assert BFZigZagVarint(-2147483648).value == -2147483648


class TestFixedFloats:
    def test_float32(self):
        assert BFProtoFloat(1.0).pack().hex() == "0000803f"
        assert BFProtoFloat(1.0).length == 4
        assert BFProtoFloat(1.0).WIRE_TYPE == WIRE_I32

    def test_double64(self):
        assert BFProtoDouble(1.0).pack().hex() == "000000000000f03f"
        assert BFProtoDouble(1.0).length == 8

    def test_bytes_roundtrip(self):
        raw = BFProtoFloat(3.5).pack()
        assert BFProtoFloat(raw).value == 3.5

    def test_bool_rejected(self):
        with pytest.raises(BFTypeException):
            BFProtoFloat(True)


class TestString:
    def test_pack_is_raw_utf8(self):
        assert BFProtoString("testing").pack() == b"testing"

    def test_unicode(self):
        assert BFProtoString("é").pack() == b"\xc3\xa9"

    def test_bytes_input_decoded(self):
        assert BFProtoString(b"hi").value == "hi"


class TestProtoKey:
    @pytest.mark.parametrize(
        "number,wire,expected_key",
        [
            (1, WIRE_VARINT, "08"),
            (2, WIRE_LEN, "12"),
            (3, WIRE_I32, "1d"),
            (16, WIRE_VARINT, "8001"),
        ],
    )
    def test_key_encoding(self, number, wire, expected_key):
        assert BFProtoKey((number << 3) | wire).pack().hex() == expected_key

    def test_key_is_structural_not_integer(self):
        # No "integer"/"scalar" tag => value mutators skip it.
        tags = BFProtoKey(0).tags
        assert "proto-key" in tags
        assert "integer" not in tags
        assert "scalar" not in tags


class TestProtoField:
    def test_scalar_field(self):
        # field 1, varint 150 => 08 96 01
        assert BFProtoField(1, BFVarint(150)).pack().hex() == "089601"

    def test_len_field_has_length_prefix(self):
        # field 2, string "testing" => 12 07 <bytes>
        f = BFProtoField(2, BFProtoString("testing"))
        assert f.pack().hex() == "1207" + b"testing".hex()
        assert f.wire_type == WIRE_LEN

    def test_buffer_wire_type_inferred_as_len(self):
        # field 5, raw bytes de ad => 2a 02 de ad
        assert BFProtoField(5, BFBuffer(b"\xde\xad")).pack().hex() == "2a02dead"

    def test_i32_wire_type_from_float(self):
        # field 4, float 1.0 => 25 00 00 80 3f
        assert BFProtoField(4, BFProtoFloat(1.0)).pack().hex() == "2500" + "00803f"

    def test_explicit_wire_type_override(self):
        # Force a fixed32 integer onto the wire as I32.
        from bitfactory import BFUInt32

        f = BFProtoField(6, BFUInt32(1), wire_type=WIRE_I32)
        assert f.pack().hex() == "35" + "01000000"

    def test_invalid_field_number(self):
        with pytest.raises(BFRangeException):
            BFProtoField(0, BFVarint(1))

    def test_uninferable_wire_type_requires_explicit(self):
        from bitfactory import BFUInt32

        with pytest.raises(BFTypeException):
            BFProtoField(1, BFUInt32(1))  # ambiguous: varint or fixed32?


class TestProtoMessage:
    def test_two_fields(self):
        m = BFProtoMessage()
        m.add_field(1, BFVarint(150)).add_field(2, BFProtoString("testing"))
        assert m.pack().hex() == "089601" + "1207" + b"testing".hex()

    def test_nested_message_is_len_framed(self):
        inner = BFProtoMessage()
        inner.add_field(1, BFVarint(1))  # => 08 01
        outer = BFProtoMessage()
        outer.add_field(3, inner)  # field 3, LEN, len 2
        assert outer.pack().hex() == "1a02" + "0801"

    def test_repeated_field_numbers(self):
        m = BFProtoMessage()
        m.add_field(1, BFVarint(1)).add_field(1, BFVarint(2))
        assert m.pack().hex() == "0801" + "0802"

    def test_wire_type_attr_for_embedding(self):
        assert BFProtoMessage.WIRE_TYPE == WIRE_LEN


class TestRegistryIntegration:
    def test_types_registered(self):
        assert get_type("proto_varint") is BFVarint
        assert get_type("proto_message") is BFProtoMessage
        assert "proto_zigzag_varint" in list_types()

    def test_tag_discovery(self):
        assert BFVarint in types_with_tag("varint")
        assert BFVarint in types_with_tag("integer")
        assert BFProtoString in types_with_tag("len")


class TestMutatorIntegration:
    def test_boundary_mutator_fuzzes_value_not_key(self):
        m = BFProtoMessage()
        m.add_field(1, BFVarint(150))
        mutatable = BFMutatable(m).add_mutator(BFIntegerBoundaryMutator())
        paths = {r.path for r in mutatable}
        assert any("_value" in p for p in paths)
        assert not any("_key" in p for p in paths)

    def test_length_prefix_is_mutated(self):
        m = BFProtoMessage()
        m.add_field(2, BFProtoString("hello"))
        mutatable = BFMutatable(m)
        for mutator in create_full_mutator_suite():
            mutatable.add_mutator(mutator)
        assert any("_len" in r.path for r in mutatable)
