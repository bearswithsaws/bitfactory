# pylint: disable=too-few-public-methods
"""BitFactory test suite"""

import pytest

from bitfactory import *  # pylint: disable=W0401,W0614
from bitfactory.exceptions import BFException, BFRangeException, BFTypeException


class TestExceptionHierarchy:
    """All library exceptions share the BFException base."""

    def test_subclasses_of_base(self):
        assert issubclass(BFRangeException, BFException)
        assert issubclass(BFTypeException, BFException)

    def test_base_catches_specific(self):
        with pytest.raises(BFException):
            BFUInt8(value=b"abc")


class TestBFUInt8:
    """Test unsigned int 8-bit"""

    def test(self):
        bf_test = BFUInt8(value=0xFF)
        assert bf_test.pack() == b"\xff"

        bf_test = BFUInt8(value=b"\xaa")
        assert bf_test.pack() == b"\xaa"

        with pytest.raises(BFRangeException):
            BFUInt8(value=b"abc")

        # Test that too large of a value is truncated
        bf_test = BFUInt8(value=0x105)
        assert bf_test.pack() == b"\x05"

        assert bf_test.length == 1


class TestBFSInt8:
    """Test signed int 8-bit"""

    def test(self):
        bf_test = BFSInt8(value=-1)
        assert bf_test.pack() == b"\xff"

        bf_test = BFSInt8(value=b"\x7f")
        assert bf_test.pack() == b"\x7f"

        with pytest.raises(BFRangeException):
            bf_test = BFSInt8(value=b"abc")

        # Test that too large of a value is truncated
        bf_test = BFSInt8(value=-0x105)
        assert bf_test.pack() == b"\xfb"

        assert bf_test.length == 1


class TestBFUInt16:
    """Test unsigned int 16-bit"""

    def test(self):
        bf_test = BFUInt16(value=0x1234)
        assert bf_test.pack() == b"\x34\x12"

        bf_test = BFUInt16(value=0x1234, endian=BFEndian.BIG)
        assert bf_test.pack() == b"\x12\x34"

        # Raw bytes round-trip identically: the bytes you supply are the bytes
        # packed, interpreted in the field's own endianness.
        bf_test = BFUInt16(value=b"\xbb\xaa", endian=BFEndian.LITTLE)
        assert bf_test.pack() == b"\xbb\xaa"

        bf_test = BFUInt16(value=b"\xbb\xaa", endian=BFEndian.BIG)
        assert bf_test.pack() == b"\xbb\xaa"

        bf_test = BFUInt16(value=1, endian=BFEndian.LITTLE)
        assert bf_test.pack() == b"\x01\x00"

        with pytest.raises(BFRangeException):
            bf_test = BFUInt16(value=b"abcd")

        # Test that too large of a value is truncated
        bf_test = BFUInt16(value=0x100000005)
        assert bf_test.pack() == b"\x05\x00"

        assert bf_test.length == 2


class TestBFSInt16:
    """Test signed int 16-bit"""

    def test(self):
        bf_test = BFSInt16(value=0x1234)
        assert bf_test.pack() == b"\x34\x12"

        bf_test = BFSInt16(value=0x1234, endian=BFEndian.BIG)
        assert bf_test.pack() == b"\x12\x34"

        bf_test = BFSInt16(value=b"\xbb\x7f", endian=BFEndian.LITTLE)
        assert bf_test.pack() == b"\xbb\x7f"

        bf_test = BFSInt16(value=b"\xbb\x7f", endian=BFEndian.BIG)
        assert bf_test.pack() == b"\xbb\x7f"

        with pytest.raises(BFRangeException):
            bf_test = BFSInt16(value=b"abcd")

        # Test that too large of a value is truncated
        bf_test = BFSInt16(value=-0x10005)
        assert bf_test.pack() == b"\xfb\xff"

        assert bf_test.length == 2


class TestBFUInt32:
    """Test unsigned int 32-bit"""

    def test(self):
        bf_test = BFUInt32(value=0x12345678)
        assert bf_test.pack() == b"\x78\x56\x34\x12"

        bf_test = BFUInt32(value=0x12345678, endian=BFEndian.BIG)
        assert bf_test.pack() == b"\x12\x34\x56\x78"

        bf_test = BFUInt32(value=b"\xdd\xcc\xbb\xaa", endian=BFEndian.LITTLE)
        assert bf_test.pack() == b"\xdd\xcc\xbb\xaa"

        bf_test = BFUInt32(value=b"\xdd\xcc\xbb\xaa", endian=BFEndian.BIG)
        assert bf_test.pack() == b"\xdd\xcc\xbb\xaa"

        with pytest.raises(BFRangeException):
            bf_test = BFUInt32(value=b"abcdef")

        # Test that too large of a value is truncated
        bf_test = BFUInt32(value=0x100000005)
        assert bf_test.pack() == b"\x05\x00\x00\x00"

        assert bf_test.length == 4


class TestBFSInt32:
    """Test signed int 32-bit"""

    def test(self):
        bf_test = BFSInt32(value=-1)
        assert bf_test.pack() == b"\xff\xff\xff\xff"

        # Test that too large of a value is truncated
        bf_test = BFSInt32(value=-0x100000005)
        assert bf_test.pack() == b"\xfb\xff\xff\xff"


class TestBFContainer:
    """Test Container"""

    def test(self):
        bf_test = BFContainer()
        bf_test.add("test", BFUInt32(value=0x1337))
        assert bf_test.pack() == b"\x37\x13\x00\x00"

        # Add a sub container
        bf_test.add("sub", BFContainer())
        assert bf_test.pack() == b"\x37\x13\x00\x00"

        bf_test.add("sub.test_sub_container", BFContainer())
        assert bf_test.pack() == b"\x37\x13\x00\x00"

        bf_test.add("sub.test_sub_container.test", BFUInt16(value=0xAABB))
        assert bf_test.pack() == b"\x37\x13\x00\x00\xbb\xaa"

        bf_test.add("sub.test_sub_container.another", BFUInt16(value=0xCCDD))
        assert bf_test.pack() == b"\x37\x13\x00\x00\xbb\xaa\xdd\xcc"

        bf_test.add("upper", BFUInt8(value=b"A"))
        assert bf_test.pack() == b"\x37\x13\x00\x00\xbb\xaa\xdd\xcc\x41"

        bf_test.add("sub.inner_insert", BFUInt8(value=b"B"))
        assert bf_test.pack() == b"\x37\x13\x00\x00\xbb\xaa\xdd\xcc\x42\x41"

        bf_test = BFContainer()
        bf_test.test = BFUInt32(value=0x1337)
        bf_test.test2 = BFUInt8(value=b"A")
        bf_test.sub = BFContainer()
        bf_test.sub.test_sub = BFContainer()
        bf_test.sub.test_val = BFUInt16(value=0xAABB)
        bf_test.sub.another_sub = BFContainer()
        bf_test.sub.another_sub.sub_item = BFUInt8(value=1)
        bf_test.sub.another_sub.sub_item2 = BFUInt8(value=2)
        bf_test.sub.test_sub.sub_sub = BFContainer()
        bf_test.sub.test_sub.sub_sub.deep_value = BFUInt32(value=0xEEFF)


class TestBFContainerShorthand:
    """Test Container shorthand syntax"""

    def test(self):
        # Shorthand
        bf_test = BFContainer()
        bf_test.test = BFUInt32(value=0x1337)
        assert bf_test.pack() == b"\x37\x13\x00\x00"

        # Add a sub caontianer
        bf_test.sub = BFContainer()
        assert bf_test.pack() == b"\x37\x13\x00\x00"

        bf_test.sub.test_sub_container = BFContainer()
        assert bf_test.pack() == b"\x37\x13\x00\x00"

        bf_test.sub.test_sub_container.test = BFUInt16(value=0xAABB)
        assert bf_test.pack() == b"\x37\x13\x00\x00\xbb\xaa"

        bf_test.sub.test_sub_container.another = BFUInt16(value=0xCCDD)
        assert bf_test.pack() == b"\x37\x13\x00\x00\xbb\xaa\xdd\xcc"

        bf_test.upper = BFUInt8(value=b"A")
        assert bf_test.pack() == b"\x37\x13\x00\x00\xbb\xaa\xdd\xcc\x41"

        bf_test.sub.inner_insert = BFUInt8(value=b"B")
        assert bf_test.pack() == b"\x37\x13\x00\x00\xbb\xaa\xdd\xcc\x42\x41"

        bf_test = BFContainer()
        bf_test.add("test", BFUInt32(value=0x1337))
        bf_test.add("test2", BFUInt8(value=b"A"))
        bf_test.add("sub", BFContainer())
        bf_test.add("sub.test_sub", BFContainer())
        bf_test.add("sub.test_val", BFUInt16(value=0xAABB))
        bf_test.add("sub.another_sub", BFContainer())
        bf_test.add("sub.another_sub.sub_item", BFUInt8(value=1))
        bf_test.add("sub.another_sub.sub_item2", BFUInt8(value=2))
        bf_test.add("sub.test_sub.sub_sub", BFContainer())
        bf_test.add("sub.test_sub.sub_sub.deep_value", BFUInt32(value=0xEEFF))


class TestBFContainerAddValidation:
    """add() with a dotted path requires the intermediate container to exist."""

    def test_missing_intermediate_raises(self):
        bf_test = BFContainer()
        bf_test.add("sub", BFContainer())
        # "sub.missing" does not exist, so adding beneath it must raise rather
        # than silently misplacing the object at the wrong depth.
        with pytest.raises(BFTypeException, match="not an existing sub-container"):
            bf_test.add("sub.missing.leaf", BFUInt8(value=1))

    def test_intermediate_not_a_container_raises(self):
        bf_test = BFContainer()
        bf_test.add("sub", BFContainer())
        bf_test.add("sub.leaf", BFUInt8(value=1))
        with pytest.raises(BFTypeException, match="not an existing sub-container"):
            bf_test.add("sub.leaf.deeper", BFUInt8(value=2))


class TestBFLength:
    """Test length-counted container"""

    def test(self):
        bf_test = BFContainer()
        bf_test.len = BFLength(BFUInt16(), BFContainer())
        bf_test.len.data = BFUInt32(value=0xAABBCCDD)
        bf_test.len.data2 = BFUInt8(value=10)
        assert bf_test.pack() == b"\x05\x00\xdd\xcc\xbb\xaa\x0a"

        bf_test = BFContainer()
        bf_test.len = BFLength(BFUInt16(endian=BFEndian.BIG), BFContainer())
        bf_test.len.data = BFUInt32(value=0xAABBCCDD)
        bf_test.len.data2 = BFUInt8(value=10)
        assert bf_test.pack() == b"\x00\x05\xdd\xcc\xbb\xaa\x0a"


def csum(data: bytes) -> int:
    checksum = 0
    for value in data:
        checksum += value
    return checksum


class TestLengthOf:
    """Test length_of computed field (object-referenced)"""

    def test(self):
        bf_test = BFContainer()
        len_data = BFContainer()
        len_data.data = BFUInt32(value=0xAABBCCDD)
        len_data.data2 = BFUInt8(value=10)
        bf_test.len = length_of(BFUInt16(), len_data)
        bf_test.len_data = len_data
        assert bf_test.pack() == b"\x05\x00\xdd\xcc\xbb\xaa\x0a"

        bf_test = BFContainer()
        len_data = BFContainer()
        len_data.data = BFUInt32(value=0xAABBCCDD)
        len_data.data2 = BFUInt8(value=10)
        bf_test.len = length_of(BFUInt16(endian=BFEndian.BIG), len_data)
        bf_test.len_data = len_data
        assert bf_test.pack() == b"\x00\x05\xdd\xcc\xbb\xaa\x0a"

        # A computed field can reference a target nested elsewhere in the tree.
        bf_test = BFContainer()
        bf_test.something = BFUInt8(value=0x11)
        bf_test.sub1 = BFContainer()
        bf_test.sub1.thing1 = BFUInt16(value=7)
        len_data = BFContainer()
        len_data.data = BFUInt32(value=0xAABBCCDD)
        len_data.data2 = BFUInt8(value=10)
        bf_test.sub1.len = length_of(BFUInt16(), len_data)
        bf_test.sub1.thing2 = BFUInt32(value=9)
        bf_test.sub1.sub2 = BFContainer()
        bf_test.sub1.sub2.len_data = len_data
        assert bf_test.pack() == b"\x11\x07\x00\x05\x00\x09\x00\x00\x00\xdd\xcc\xbb\xaa\x0a"


class TestChecksumOf:
    """Test checksum_of computed field (object-referenced)"""

    def test(self):
        bf_test = BFContainer()
        csum_data = BFContainer()
        csum_data.data = BFUInt32(value=0xAABBCCDD)
        csum_data.data2 = BFUInt8(value=10)
        bf_test.len = checksum_of(BFUInt16(), csum, csum_data)
        bf_test.csum_data = csum_data
        assert bf_test.pack() == b"\x18\x03\xdd\xcc\xbb\xaa\x0a"

        bf_test = BFContainer()
        csum_data = BFContainer()
        csum_data.data = BFUInt32(value=0xAABBCCDD)
        csum_data.data2 = BFUInt8(value=10)
        bf_test.len = checksum_of(BFUInt16(endian=BFEndian.BIG), csum, csum_data)
        bf_test.csum_data = csum_data
        assert bf_test.pack() == b"\x03\x18\xdd\xcc\xbb\xaa\x0a"

        bf_test = BFContainer()
        bf_test.something = BFUInt8(value=0x11)
        bf_test.sub1 = BFContainer()
        bf_test.sub1.thing1 = BFUInt16(value=7)
        csum_data = BFContainer()
        csum_data.data = BFUInt32(value=0xAABBCCDD)
        csum_data.data2 = BFUInt8(value=10)
        bf_test.sub1.len = checksum_of(BFUInt16(), csum, csum_data)
        bf_test.sub1.thing2 = BFUInt32(value=9)
        bf_test.sub1.sub2 = BFContainer()
        bf_test.sub1.sub2.csum_data = csum_data
        assert bf_test.pack() == b"\x11\x07\x00\x18\x03\x09\x00\x00\x00\xdd\xcc\xbb\xaa\x0a"

    def test_multi_target_range(self):
        """A checksum can span a range of siblings without a wrapper container."""
        bf_test = BFContainer()
        bf_test.a = BFUInt16(value=0x1122, endian=BFEndian.BIG)
        bf_test.b = BFUInt16(value=0x3344, endian=BFEndian.BIG)
        bf_test.ck = checksum_of(BFUInt8(), csum, bf_test.a, bf_test.b)
        # ck = 0x11+0x22+0x33+0x44 = 0xAA
        assert bf_test.pack() == b"\x11\x22\x33\x44\xaa"


class TestEmbeddability:
    """A referencing sub-structure keeps working after being reparented."""

    def _build_tlv(self):
        """A reusable length-prefixed record: [len][payload]."""
        tlv = BFContainer()
        payload = BFContainer()
        payload.data = BFUInt32(value=0xAABBCCDD)
        tlv.length = length_of(BFUInt8(), payload)
        tlv.payload = payload
        return tlv

    def test_same_bytes_at_root_and_when_nested(self):
        # Object references resolve to the held node, not an absolute path, so
        # the record packs identically standalone and when embedded deeper.
        standalone = self._build_tlv()
        assert standalone.pack() == b"\x04\xdd\xcc\xbb\xaa"

        outer = BFContainer()
        outer.header = BFUInt8(value=0x01)
        outer.record = self._build_tlv()
        assert outer.pack() == b"\x01\x04\xdd\xcc\xbb\xaa"


class TestCountOf:
    """Test count_of computed field."""

    def test(self):
        bf_test = BFContainer()
        items = BFContainer()
        items.a = BFUInt8(value=0xAA)
        items.b = BFUInt8(value=0xBB)
        items.c = BFUInt8(value=0xCC)
        bf_test.count = count_of(BFUInt8(), items)
        bf_test.items = items
        assert bf_test.pack() == b"\x03\xaa\xbb\xcc"


class TestComputedValidation:
    """Validation and error handling for computed fields."""

    def test_fn_not_callable(self):
        with pytest.raises(BFTypeException, match="fn must be callable"):
            BFComputed(BFUInt16(), "not_a_function")

    def test_field_not_bf_type(self):
        with pytest.raises(BFTypeException, match="field must be a BitFactory type"):
            BFComputed("not_a_field", lambda ctx: 0)

    def test_checksum_func_not_callable(self):
        with pytest.raises(BFTypeException, match="func must be callable"):
            checksum_of(BFUInt16(), "not_a_function")

    def test_length_target_not_bf_type(self):
        with pytest.raises(BFTypeException, match="targets must be BitFactory types"):
            length_of(BFUInt16(), "not_a_node")

    def test_count_target_not_container(self):
        with pytest.raises(BFTypeException, match="count_of target must be a BFContainer"):
            count_of(BFUInt8(), BFUInt8())


# class TestPrint():
#     """Test pretty-print"""

#     def test(self):
#         bf_test = BFUInt8(value=0x41)
#         print(bf_test)

#         bf_test = BFContainer()
#         bf_test.test = BFUInt32(value=0x1337)
#         bf_test.test2 = BFUInt8(value=b"A")
#         bf_test.sub = BFContainer()
#         bf_test.sub.test_val = BFUInt16(value=0xAABB)
#         bf_test.sub.another_sub = BFContainer()
#         bf_test.sub.another_sub.sub_item = BFUInt8(value=-1)
#         bf_test.sub.test = BFContainer()
#         bf_test.sub.another_sub.out_of_order = BFUInt16(value=0x1122)
#         bf_test.sub.test.deep_value = BFUInt32(value=1337)
#         bf_test.sub.test.sub_sub = BFContainer()
#         bf_test.sub.test.sub_sub.deep_value = BFUInt32(value=1337)
#         print(bf_test)
#         print(bf_test.pack())

#         print("")
#         bf_test = BFContainer()
#         bf_test.add("test", BFUInt32(value=0x1337))
#         bf_test.add("test2", BFUInt8(value=b"A"))
#         bf_test.add("sub", BFContainer())
#         bf_test.add("sub.test_val", BFUInt16(value=0xAABB))
#         bf_test.add("sub.another_sub", BFContainer())
#         bf_test.add("sub.another_sub.sub_item", BFUInt8(value=1))
#         bf_test.add("sub.another_sub.sub_item2", BFUInt8(value=2))
#         bf_test.add("sub.test.sub_sub", BFContainer())
#         bf_test.add("sub.test.sub_sub.deep_value", BFUInt32(value=0xEEFF))
#         print(bf_test)
#         print(bf_test.pack())

#         bf_test = BFContainer()
#         bf_test.test = BFUInt32(value=0x1337)
#         bf_test.test2 = BFUInt8(value=b"A")
#         bf_test.sub = BFLength(BFUInt32(), BFContainer())
#         bf_test.sub.test_val = BFUInt16(value=0xAABB)
#         bf_test.sub.another_sub = BFContainer()
#         bf_test.sub.another_sub.sub_item = BFUInt8(value=-1)
#         bf_test.sub.test = BFContainer()
#         bf_test.sub.another_sub.out_of_order = BFUInt16(value=0x1122)
#         bf_test.sub.test.deep_value = BFUInt32(value=1337)
#         bf_test.sub.test.sub_sub = BFContainer()
#         bf_test.sub.test.sub_sub.deep_value = BFUInt32(value=1337)
#         bf_test.sub.buf = BFBuffer(value=b"A" * 100)
#         print(bf_test)
#         print(bf_test.pack())
