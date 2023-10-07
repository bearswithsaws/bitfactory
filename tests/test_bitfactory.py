# pylint: disable=too-few-public-methods
"""BitFactory test suite
"""
import pytest

from bitfactory import *  # pylint: disable=W0401,W0614
from bitfactory.exceptions import BFRangeException


class TestBFUInt8():
    """Test unsigned int 8-bit"""

    def test(self):
        bf_test = BFUInt8(value=0xFF)
        assert b"\xff" == bf_test.pack()

        bf_test = BFUInt8(value=b"\xaa")
        assert b"\xaa" == bf_test.pack()

        with pytest.raises(BFRangeException):
            BFUInt8(value=b"abc")

        # Test that too large of a value is truncated
        bf_test = BFUInt8(value=0x105)
        assert b"\x05" == bf_test.pack()

        assert bf_test.length == 1


class TestBFSInt8():
    """Test signed int 8-bit"""

    def test(self):
        bf_test = BFSInt8(value=-1)
        assert b"\xff" == bf_test.pack()

        bf_test = BFSInt8(value=b"\x7f")
        assert b"\x7f" == bf_test.pack()

        with pytest.raises(BFRangeException):
            bf_test = BFSInt8(value=b"abc")

        # Test that too large of a value is truncated
        bf_test = BFSInt8(value=-0x105)
        assert b"\xfb" == bf_test.pack()

        assert bf_test.length == 1


class TestBFUInt16():
    """Test unsigned int 16-bit"""

    def test(self):
        bf_test = BFUInt16(value=0x1234)
        assert b"\x34\x12" == bf_test.pack()

        bf_test = BFUInt16(value=0x1234, endian=BFEndian.BIG)
        assert b"\x12\x34" == bf_test.pack()

        bf_test = BFUInt16(value=b"\xbb\xaa", endian=BFEndian.LITTLE)
        assert b"\xbb\xaa" == bf_test.pack()

        bf_test = BFUInt16(value=b"\xbb\xaa", endian=BFEndian.BIG)
        assert b"\xaa\xbb" == bf_test.pack()

        bf_test = BFUInt16(value=1, endian=BFEndian.LITTLE)
        assert b"\x01\x00" == bf_test.pack()

        with pytest.raises(BFRangeException):
            bf_test = BFUInt16(value=b"abcd")

        # Test that too large of a value is truncated
        bf_test = BFUInt16(value=0x100000005)
        assert b"\x05\x00" == bf_test.pack()

        assert bf_test.length == 2


class TestBFSInt16():
    """Test signed int 16-bit"""

    def test(self):
        bf_test = BFSInt16(value=0x1234)
        assert b"\x34\x12" == bf_test.pack()

        bf_test = BFSInt16(value=0x1234, endian=BFEndian.BIG)
        assert b"\x12\x34" == bf_test.pack()

        bf_test = BFSInt16(value=b"\xbb\x7f", endian=BFEndian.LITTLE)
        assert b"\xbb\x7f" == bf_test.pack()

        bf_test = BFSInt16(value=b"\xbb\x7f", endian=BFEndian.BIG)
        assert b"\x7f\xbb" == bf_test.pack()

        with pytest.raises(BFRangeException):
            bf_test = BFSInt16(value=b"abcd")

        # Test that too large of a value is truncated
        bf_test = BFSInt16(value=-0x10005)
        assert b"\xfb\xff" == bf_test.pack()

        assert bf_test.length == 2


class TestBFUInt32():
    """Test unsigned int 32-bit"""

    def test(self):
        bf_test = BFUInt32(value=0x12345678)
        assert b"\x78\x56\x34\x12" == bf_test.pack()

        bf_test = BFUInt32(value=0x12345678, endian=BFEndian.BIG)
        assert b"\x12\x34\x56\x78" == bf_test.pack()

        bf_test = BFUInt32(value=b"\xdd\xcc\xbb\xaa", endian=BFEndian.LITTLE)
        assert b"\xdd\xcc\xbb\xaa" == bf_test.pack()

        bf_test = BFUInt32(value=b"\xdd\xcc\xbb\xaa", endian=BFEndian.BIG)
        assert b"\xaa\xbb\xcc\xdd" == bf_test.pack()

        with pytest.raises(BFRangeException):
            bf_test = BFUInt32(value=b"abcdef")

        # Test that too large of a value is truncated
        bf_test = BFUInt32(value=0x100000005)
        assert b"\x05\x00\x00\x00" == bf_test.pack()

        assert bf_test.length == 4


class TestBFSInt32():
    """Test signed int 32-bit"""

    def test(self):
        bf_test = BFSInt32(value=-1)
        assert b"\xff\xff\xff\xff" == bf_test.pack()

        # Test that too large of a value is truncated
        bf_test = BFSInt32(value=-0x100000005)
        assert b"\xfb\xff\xff\xff" == bf_test.pack()


class TestBFContainer():
    """Test Container"""

    def test(self):
        bf_test = BFContainer()
        bf_test.add("test", BFUInt32(value=0x1337))
        assert b"\x37\x13\x00\x00" == bf_test.pack()

        # Add a sub container
        bf_test.add("sub", BFContainer())
        assert b"\x37\x13\x00\x00" == bf_test.pack()

        bf_test.add("sub.test_sub_container", BFContainer())
        assert b"\x37\x13\x00\x00" == bf_test.pack()

        bf_test.add("sub.test_sub_container.test", BFUInt16(value=0xAABB))
        assert b"\x37\x13\x00\x00\xbb\xaa" == bf_test.pack()

        bf_test.add("sub.test_sub_container.another", BFUInt16(value=0xCCDD))
        assert b"\x37\x13\x00\x00\xbb\xaa\xdd\xcc" == bf_test.pack()

        bf_test.add("upper", BFUInt8(value=b"A"))
        assert b"\x37\x13\x00\x00\xbb\xaa\xdd\xcc\x41" == bf_test.pack()

        bf_test.add("sub.inner_insert", BFUInt8(value=b"B"))
        assert b"\x37\x13\x00\x00\xbb\xaa\xdd\xcc\x42\x41" == bf_test.pack()

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


class TestBFContainerShorthand():
    """Test Container shorthand syntax"""

    def test(self):
        # Shorthand
        bf_test = BFContainer()
        bf_test.test = BFUInt32(value=0x1337)
        assert b"\x37\x13\x00\x00" == bf_test.pack()

        # Add a sub caontianer
        bf_test.sub = BFContainer()
        assert b"\x37\x13\x00\x00" == bf_test.pack()

        bf_test.sub.test_sub_container = BFContainer()
        assert b"\x37\x13\x00\x00" == bf_test.pack()

        bf_test.sub.test_sub_container.test = BFUInt16(value=0xAABB)
        assert b"\x37\x13\x00\x00\xbb\xaa" == bf_test.pack()

        bf_test.sub.test_sub_container.another = BFUInt16(value=0xCCDD)
        assert b"\x37\x13\x00\x00\xbb\xaa\xdd\xcc" == bf_test.pack()

        bf_test.upper = BFUInt8(value=b"A")
        assert b"\x37\x13\x00\x00\xbb\xaa\xdd\xcc\x41" == bf_test.pack()

        bf_test.sub.inner_insert = BFUInt8(value=b"B")
        assert b"\x37\x13\x00\x00\xbb\xaa\xdd\xcc\x42\x41" == bf_test.pack()

        bf_test = BFContainer()
        bf_test.add("test", BFUInt32(value=0x1337))
        bf_test.add("test2", BFUInt8(value=b"A"))
        bf_test.add("sub", BFContainer())
        bf_test.add("sub.test_val", BFUInt16(value=0xAABB))
        bf_test.add("sub.another_sub", BFContainer())
        bf_test.add("sub.another_sub.sub_item", BFUInt8(value=1))
        bf_test.add("sub.another_sub.sub_item2", BFUInt8(value=2))
        bf_test.add("sub.test.sub_sub", BFContainer())
        bf_test.add("sub.test.sub_sub.deep_value", BFUInt32(value=0xEEFF))


class TestBFLength():
    """Test length-counted container"""

    def test(self):
        bf_test = BFContainer()
        bf_test.len = BFLength(BFUInt16(), BFContainer())
        bf_test.len.data = BFUInt32(value=0xAABBCCDD)
        bf_test.len.data2 = BFUInt8(value=10)
        assert b"\x05\x00\xdd\xcc\xbb\xaa\x0a" == bf_test.pack()

        bf_test = BFContainer()
        bf_test.len = BFLength(BFUInt16(endian=BFEndian.BIG), BFContainer())
        bf_test.len.data = BFUInt32(value=0xAABBCCDD)
        bf_test.len.data2 = BFUInt8(value=10)
        assert b"\x00\x05\xdd\xcc\xbb\xaa\x0a" == bf_test.pack()


class TestBFLengthRef():
    """Test length-counted container"""

    def test(self):
        bf_test = BFContainer()
        bf_test.len = BFLengthRef(BFUInt16(), "len_data")
        bf_test.len_data = BFContainer()
        bf_test.len_data.data = BFUInt32(value=0xAABBCCDD)
        bf_test.len_data.data2 = BFUInt8(value=10)
        # print(bf_test.pretty_print())
        # print(bf_test.pack())
        assert b"\x05\x00\xdd\xcc\xbb\xaa\x0a" == bf_test.pack()

        bf_test = BFContainer()
        bf_test.len = BFLengthRef(BFUInt16(endian=BFEndian.BIG), "len_data")
        bf_test.len_data = BFContainer()
        bf_test.len_data.data = BFUInt32(value=0xAABBCCDD)
        bf_test.len_data.data2 = BFUInt8(value=10)
        assert b"\x00\x05\xdd\xcc\xbb\xaa\x0a" == bf_test.pack()

        bf_test = BFContainer()
        bf_test.something = BFUInt8(value=0x11)
        bf_test.sub1 = BFContainer()
        bf_test.sub1.thing1 = BFUInt16(value=7)
        bf_test.sub1.len = BFLengthRef(BFUInt16(), "sub1.sub2.len_data")
        bf_test.sub1.thing2 = BFUInt32(value=9)
        bf_test.sub1.sub2 = BFContainer()
        bf_test.sub1.sub2.len_data = BFContainer()
        bf_test.sub1.sub2.len_data.data = BFUInt32(value=0xAABBCCDD)
        bf_test.sub1.sub2.len_data.data2 = BFUInt8(value=10)
        # print(bf_test.pretty_print())
        # print(bf_test.pack())
        assert(
            b"\x11\x07\x00\x05\x00\x09\x00\x00\x00\xdd\xcc\xbb\xaa\x0a"
            == bf_test.pack()
        )


def csum(data: bytes) -> int:
    checksum = 0
    for value in data:
        checksum += value
    return checksum


class TestBFCallableRef():
    """Test callable ref container"""

    def test(self):
        bf_test = BFContainer()
        bf_test.len = BFCallableRef(BFUInt16(), csum, "csum_data")
        bf_test.csum_data = BFContainer()
        bf_test.csum_data.data = BFUInt32(value=0xAABBCCDD)
        bf_test.csum_data.data2 = BFUInt8(value=10)
        # print(bf_test.pretty_print())
        # print(bf_test.pack())
        assert b"\x18\x03\xdd\xcc\xbb\xaa\x0a" == bf_test.pack()

        bf_test = BFContainer()
        bf_test.len = BFCallableRef(BFUInt16(endian=BFEndian.BIG), csum, "csum_data")
        bf_test.csum_data = BFContainer()
        bf_test.csum_data.data = BFUInt32(value=0xAABBCCDD)
        bf_test.csum_data.data2 = BFUInt8(value=10)
        assert b"\x03\x18\xdd\xcc\xbb\xaa\x0a" == bf_test.pack()

        bf_test = BFContainer()
        bf_test.something = BFUInt8(value=0x11)
        bf_test.sub1 = BFContainer()
        bf_test.sub1.thing1 = BFUInt16(value=7)
        bf_test.sub1.len = BFCallableRef(BFUInt16(), csum, "sub1.sub2.csum_data")
        bf_test.sub1.thing2 = BFUInt32(value=9)
        bf_test.sub1.sub2 = BFContainer()
        bf_test.sub1.sub2.csum_data = BFContainer()
        bf_test.sub1.sub2.csum_data.data = BFUInt32(value=0xAABBCCDD)
        bf_test.sub1.sub2.csum_data.data2 = BFUInt8(value=10)
        # print(bf_test.pretty_print())
        # print(bf_test.pack())
        assert(
            b"\x11\x07\x00\x18\x03\x09\x00\x00\x00\xdd\xcc\xbb\xaa\x0a"
            == bf_test.pack()
        )


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
