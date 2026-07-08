"""Tests for the computed-field primitive and its context accessor."""

from bitfactory import (
    BFComputed,
    BFContainer,
    BFUInt8,
    BFUInt16,
    BFUInt32,
    ComputeContext,
    checksum_of,
    count_of,
    length_of,
)
from bitfactory.mutators import BFIntegerBoundaryMutator, BFMutatable


class TestComputeContext:
    """The context resolves referenced nodes into bytes/value/length/count."""

    def test_bytes_concatenates_targets(self):
        a = BFUInt8(0xAA)
        b = BFUInt16(0xBBCC)  # little-endian -> cc bb
        computed = BFComputed(BFUInt8(), lambda ctx: 0)
        ctx = ComputeContext(computed)
        assert ctx.bytes(a, b) == b"\xaa\xcc\xbb"

    def test_value_and_length(self):
        target = BFUInt32(0x11223344)
        ctx = ComputeContext(BFComputed(BFUInt8(), lambda c: 0))
        assert ctx.value(target) == 0x11223344
        assert ctx.length(target) == 4

    def test_count(self):
        container = BFContainer()
        container.a = BFUInt8(1)
        container.b = BFUInt8(2)
        ctx = ComputeContext(BFComputed(BFUInt8(), lambda c: 0))
        assert ctx.count(container) == 2


class TestComputedLambda:
    """The escape-hatch lambda can do arbitrary arithmetic over the tree."""

    def test_custom_expression(self):
        frame = BFContainer()
        hdr = BFContainer()
        hdr.a = BFUInt8(0x01)
        body = BFContainer()
        body.b = BFUInt8(0x02)
        # length of hdr+body plus a constant header offset of 4.
        frame.total = BFComputed(BFUInt8(), lambda ctx: len(ctx.bytes(hdr, body)) + 4)
        frame.hdr = hdr
        frame.body = body
        assert frame.pack() == b"\x06\x01\x02"


class TestComputedValueReflectsTree:
    """A computed field's value re-reads the current tree each pack."""

    def test_value_updates_when_target_changes(self):
        body = BFContainer()
        body.data = BFUInt16(0x0000)
        length = length_of(BFUInt8(), body)

        container = BFContainer()
        container.length = length
        container.body = body
        assert container.pack() == b"\x02\x00\x00"

        # Grow the referenced region; the length recomputes automatically.
        body.more = BFUInt16(0x1111)
        assert container.pack() == b"\x04\x00\x00\x11\x11"


class TestPrettyPrint:
    """Computed leaves render on a single line, labeled by their field name."""

    def test_pretty_print_line(self):
        body = BFContainer()
        body.data = BFUInt8(0x42)
        container = BFContainer()
        container.length = length_of(BFUInt8(), body)
        container.body = body
        rendered = str(container)
        assert "|= computed 0x1 : length" in rendered


class TestChecksumMultiTarget:
    """checksum_of spans several targets in order without a wrapper."""

    def test_two_targets(self):
        def add(data: bytes) -> int:
            return sum(data) & 0xFF

        frame = BFContainer()
        frame.a = BFUInt8(0x10)
        frame.b = BFUInt8(0x20)
        frame.ck = checksum_of(BFUInt8(), add, frame.a, frame.b)
        assert frame.pack() == b"\x10\x20\x30"


class TestMutability:
    """Default mutability of the helper-built computed fields."""

    def test_length_is_mutable_by_default(self):
        body = BFContainer()
        body.data = BFUInt8(0)
        assert length_of(BFUInt8(), body).mutable is True

    def test_checksum_and_count_are_not_mutable(self):
        body = BFContainer()
        body.data = BFUInt8(0)
        assert checksum_of(BFUInt8(), sum, body).mutable is False
        assert count_of(BFUInt8(), body).mutable is False

    def test_raw_computed_defaults_not_mutable(self):
        assert BFComputed(BFUInt8(), lambda ctx: 0).mutable is False

    def test_count_of_is_skipped_by_mutators(self):
        container = BFContainer()
        items = BFContainer()
        items.a = BFUInt8(1)
        container.count = count_of(BFUInt8(), items)
        container.items = items

        mut = BFMutatable(container).add_mutator(BFIntegerBoundaryMutator())
        paths = {r.path for r in mut}
        assert "count" not in paths
        assert "items.a" in paths

    def test_count_of_can_opt_in_to_mutation(self):
        container = BFContainer()
        items = BFContainer()
        items.a = BFUInt8(1)
        container.count = count_of(BFUInt8(), items, mutable=True)
        container.items = items

        mut = BFMutatable(container).add_mutator(BFIntegerBoundaryMutator())
        paths = {r.path for r in mut}
        assert "count" in paths
