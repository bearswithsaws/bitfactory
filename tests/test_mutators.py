# pylint: disable=too-few-public-methods
"""BitFactory Mutators test suite"""

from bitfactory import (
    BFBuffer,
    BFContainer,
    BFLength,
    BFSInt8,
    BFSInt16,
    BFSInt32,
    BFUInt8,
    BFUInt16,
    BFUInt32,
    checksum_of,
    length_of,
)
from bitfactory.mutators import (
    BFBitFlipMutator,
    BFBufferContentMutator,
    BFBufferLengthMutator,
    BFBufferNullTerminationMutator,
    BFIntegerBitPatternMutator,
    BFIntegerBoundaryMutator,
    BFIntegerSignMutator,
    BFIntegerSpecialValueMutator,
    BFMutatable,
    MutationResult,
    TraversalOrder,
    create_buffer_mutator_suite,
    create_full_mutator_suite,
    create_integer_mutator_suite,
    mutate,
)


class TestTraversalOrder:
    """Test TraversalOrder enum"""

    def test_enum_values(self):
        """Test that all traversal orders exist"""
        assert TraversalOrder.DFS_PREORDER is not None
        assert TraversalOrder.DFS_POSTORDER is not None
        assert TraversalOrder.BFS is not None


class TestMetadataSystem:
    """Test the generic metadata system"""

    def test_metadata_has_references(self):
        """Test that CWE-based mutators have references in metadata"""
        mutator = BFIntegerBoundaryMutator()
        metadata = mutator.metadata

        assert "references" in metadata
        assert len(metadata["references"]) > 0

        # Check structure of references
        ref = metadata["references"][0]
        assert "source" in ref
        assert "id" in ref
        assert ref["source"] == "CWE"

    def test_metadata_has_tags(self):
        """Test that mutators have tags"""
        mutator = BFIntegerBoundaryMutator()
        metadata = mutator.metadata

        assert "tags" in metadata
        assert isinstance(metadata["tags"], list)
        assert "overflow" in metadata["tags"]

    def test_metadata_has_category(self):
        """Test that mutators have category"""
        mutator = BFIntegerBoundaryMutator()
        metadata = mutator.metadata

        assert "category" in metadata
        assert metadata["category"] == "integer-arithmetic"

    def test_non_cwe_mutator_metadata(self):
        """Test that non-CWE mutators have appropriate metadata"""
        mutator = BFBitFlipMutator()
        metadata = mutator.metadata

        # Should not have CWE references
        assert "references" not in metadata or len(metadata.get("references", [])) == 0

        # Should have tags and category
        assert "tags" in metadata
        assert "bit-flip" in metadata["tags"]
        assert "category" in metadata

    def test_mutation_result_contains_metadata(self):
        """Test that MutationResult includes full metadata"""
        bf_val = BFUInt8(value=42)
        mut = BFMutatable(bf_val)
        mut.add_mutator(BFIntegerBoundaryMutator())

        result = next(iter(mut))

        assert hasattr(result, "metadata")
        assert isinstance(result.metadata, dict)
        assert "references" in result.metadata


class TestBFIntegerBoundaryMutator:
    """Test integer boundary mutator"""

    def test_properties(self):
        """Test mutator properties"""
        mutator = BFIntegerBoundaryMutator()
        assert mutator.name == "Integer Boundary Mutator"
        assert "references" in mutator.metadata
        assert mutator.applies_to_tags == frozenset({"integer"})
        assert mutator.can_mutate(BFUInt8(0))
        assert mutator.can_mutate(BFSInt32(0))

    def test_can_mutate(self):
        """Test type support checking"""
        mutator = BFIntegerBoundaryMutator()
        assert mutator.can_mutate(BFUInt8(0))
        assert mutator.can_mutate(BFSInt16(value=0))
        assert mutator.can_mutate(BFUInt32(0))
        assert not mutator.can_mutate(BFBuffer(b"test"))

    def test_uint8_boundaries(self):
        """Test unsigned 8-bit boundary mutations"""
        mutator = BFIntegerBoundaryMutator()
        bf_val = BFUInt8(value=100)

        mutations = list(mutator.mutate(bf_val))
        values = [m[0] for m in mutations]

        assert 255 in values  # MAX_UNSIGNED_8
        assert 256 in values  # MAX_UNSIGNED_8 + 1 (overflow)
        assert 0 in values  # MIN_UNSIGNED_8
        assert -1 in values  # Underflow
        assert 1 in values  # One

    def test_sint8_boundaries(self):
        """Test signed 8-bit boundary mutations"""
        mutator = BFIntegerBoundaryMutator()
        bf_val = BFSInt8(value=0)

        mutations = list(mutator.mutate(bf_val))
        values = [m[0] for m in mutations]

        assert 127 in values  # MAX_SIGNED_8
        assert 128 in values  # Overflow
        assert -128 in values  # MIN_SIGNED_8
        assert -129 in values  # Underflow
        assert -1 in values

    def test_uint16_boundaries(self):
        """Test unsigned 16-bit boundary mutations"""
        mutator = BFIntegerBoundaryMutator()
        bf_val = BFUInt16(value=1000)

        mutations = list(mutator.mutate(bf_val))
        values = [m[0] for m in mutations]

        assert 65535 in values  # MAX_UNSIGNED_16
        assert 65536 in values  # Overflow
        assert 0 in values

    def test_uint32_boundaries(self):
        """Test unsigned 32-bit boundary mutations"""
        mutator = BFIntegerBoundaryMutator()
        bf_val = BFUInt32(value=1000)

        mutations = list(mutator.mutate(bf_val))
        values = [m[0] for m in mutations]

        assert 0xFFFFFFFF in values  # MAX_UNSIGNED_32
        assert 0x100000000 in values  # Overflow
        assert 0 in values


class TestBFIntegerSignMutator:
    """Test integer sign mutator"""

    def test_properties(self):
        """Test mutator properties"""
        mutator = BFIntegerSignMutator()
        assert "references" in mutator.metadata
        refs = [r["id"] for r in mutator.metadata["references"]]
        assert "194" in refs
        assert "195" in refs

    def test_sign_bit_values(self):
        """Test that sign bit mutations are generated"""
        mutator = BFIntegerSignMutator()
        bf_val = BFUInt8(value=0)

        mutations = list(mutator.mutate(bf_val))
        values = [m[0] for m in mutations]

        assert 0x80 in values
        assert 0x7F in values

    def test_signed_type_mutations(self):
        """Test mutations for signed types"""
        mutator = BFIntegerSignMutator()
        bf_val = BFSInt16(value=0)

        mutations = list(mutator.mutate(bf_val))
        values = [m[0] for m in mutations]

        assert -1 in values
        assert 0x80 in values


class TestBFIntegerSpecialValueMutator:
    """Test integer special value mutator"""

    def test_properties(self):
        """Test mutator properties"""
        mutator = BFIntegerSpecialValueMutator()
        refs = [r["id"] for r in mutator.metadata["references"]]
        assert "369" in refs  # Divide by zero
        assert "682" in refs

    def test_special_values(self):
        """Test special value mutations"""
        mutator = BFIntegerSpecialValueMutator()
        bf_val = BFUInt16(value=100)

        mutations = list(mutator.mutate(bf_val))
        values = [m[0] for m in mutations]

        assert 0 in values
        assert 1 in values
        assert 4 in values
        assert 16 in values
        assert 256 in values


class TestBFIntegerBitPatternMutator:
    """Test integer bit pattern mutator"""

    def test_properties(self):
        """Test mutator properties"""
        mutator = BFIntegerBitPatternMutator()
        refs = [r["id"] for r in mutator.metadata["references"]]
        assert "704" in refs

    def test_bit_patterns_uint8(self):
        """Test bit pattern mutations for 8-bit"""
        mutator = BFIntegerBitPatternMutator()
        bf_val = BFUInt8(value=0)

        mutations = list(mutator.mutate(bf_val))
        values = [m[0] for m in mutations]

        assert 0xFF in values
        assert 0xAA in values
        assert 0x55 in values
        assert 1 in values
        assert 2 in values
        assert 0x0F in values

    def test_bit_patterns_uint32(self):
        """Test bit pattern mutations for 32-bit"""
        mutator = BFIntegerBitPatternMutator()
        bf_val = BFUInt32(value=0)

        mutations = list(mutator.mutate(bf_val))
        values = [m[0] for m in mutations]

        assert 0xFFFFFFFF in values
        assert 0xAAAAAAAA in values
        assert 0x55555555 in values
        assert 0x0000FFFF in values
        assert 0xFFFF0000 in values


class TestBFBitFlipMutator:
    """Test bit flip mutator"""

    def test_properties(self):
        """Test mutator properties"""
        mutator = BFBitFlipMutator()
        assert mutator.name == "Bit Flip Mutator"
        assert "bit-flip" in mutator.metadata["tags"]
        assert (
            "references" not in mutator.metadata or len(mutator.metadata.get("references", [])) == 0
        )

    def test_uint8_bit_flips(self):
        """Test that UInt8 generates exactly 8 mutations"""
        mutator = BFBitFlipMutator()
        bf_val = BFUInt8(value=0b10101010)  # 0xAA

        mutations = list(mutator.mutate(bf_val))

        # Should have exactly 8 mutations (one per bit)
        assert len(mutations) == 8

        # Each mutation should flip exactly one bit
        original = 0xAA
        for i, (value, _desc) in enumerate(mutations):
            expected = original ^ (1 << i)
            assert value == expected, f"Bit {i}: expected {expected}, got {value}"

    def test_uint16_bit_flips(self):
        """Test that UInt16 generates exactly 16 mutations"""
        mutator = BFBitFlipMutator()
        bf_val = BFUInt16(value=0x1234)

        mutations = list(mutator.mutate(bf_val))
        assert len(mutations) == 16

    def test_uint32_bit_flips(self):
        """Test that UInt32 generates exactly 32 mutations"""
        mutator = BFBitFlipMutator()
        bf_val = BFUInt32(value=0x12345678)

        mutations = list(mutator.mutate(bf_val))
        assert len(mutations) == 32

    def test_buffer_bit_flips(self):
        """Test buffer bit flips"""
        mutator = BFBitFlipMutator()
        bf_val = BFBuffer(b"\xaa\x55")  # 2 bytes

        mutations = list(mutator.mutate(bf_val))

        # Should have 16 mutations (8 bits * 2 bytes)
        assert len(mutations) == 16

        # Check first byte mutations
        for i in range(8):
            value, desc = mutations[i]
            expected = bytearray(b"\xaa\x55")
            expected[0] ^= 1 << i
            assert value == bytes(expected)

    def test_bit_flip_description(self):
        """Test that descriptions are informative"""
        mutator = BFBitFlipMutator()
        bf_val = BFUInt8(value=0xFF)

        mutations = list(mutator.mutate(bf_val))
        _, desc = mutations[0]

        assert "Flip bit" in desc
        assert "0x" in desc


class TestBFBufferLengthMutator:
    """Test buffer length mutator"""

    def test_properties(self):
        """Test mutator properties"""
        mutator = BFBufferLengthMutator()
        refs = [r["id"] for r in mutator.metadata["references"]]
        assert "120" in refs
        assert "787" in refs
        assert mutator.applies_to_tags == frozenset({"buffer"})
        assert mutator.can_mutate(BFBuffer(b"test"))

    def test_can_mutate(self):
        """Test type support"""
        mutator = BFBufferLengthMutator()
        assert mutator.can_mutate(BFBuffer(b"test"))
        assert not mutator.can_mutate(BFUInt8(0))

    def test_length_mutations(self):
        """Test buffer length mutations"""
        mutator = BFBufferLengthMutator()
        bf_val = BFBuffer(b"test data here")

        mutations = list(mutator.mutate(bf_val))

        assert any(m[0] == b"" for m in mutations)
        assert any(m[0] == b"\x00" for m in mutations)
        lengths = [len(m[0]) for m in mutations]
        assert 1 in lengths
        assert 256 in lengths


class TestBFBufferContentMutator:
    """Test buffer content mutator"""

    def test_properties(self):
        """Test mutator properties"""
        mutator = BFBufferContentMutator()
        refs = [r["id"] for r in mutator.metadata["references"]]
        assert "134" in refs
        assert "78" in refs

    def test_content_mutations(self):
        """Test buffer content mutations"""
        mutator = BFBufferContentMutator()
        bf_val = BFBuffer(b"test")

        mutations = list(mutator.mutate(bf_val))
        values = [m[0] for m in mutations]

        assert any(b"%s" in v for v in values)
        assert any(b"%n" in v for v in values)
        assert any(v == b"\x00" * 16 for v in values)
        assert any(b"/../" in v for v in values)


class TestBFBufferNullTerminationMutator:
    """Test buffer null termination mutator"""

    def test_properties(self):
        """Test mutator properties"""
        mutator = BFBufferNullTerminationMutator()
        refs = [r["id"] for r in mutator.metadata["references"]]
        assert "170" in refs
        assert "126" in refs

    def test_null_mutations(self):
        """Test null termination mutations"""
        mutator = BFBufferNullTerminationMutator()
        bf_val = BFBuffer(b"hello\x00")

        mutations = list(mutator.mutate(bf_val))
        values = [m[0] for m in mutations]

        assert b"hello" in values
        assert any(v.endswith(b"\x00\x00\x00") for v in values)
        assert b"AAAA\x00BBBB" in values


class TestBFMutatable:
    """Test BFMutatable wrapper"""

    def test_basic_wrapping(self):
        """Test wrapping a basic type"""
        bf_val = BFUInt32(value=100)
        mut = BFMutatable(bf_val)

        assert mut._root is bf_val
        assert len(mut.mutators) == 0

    def test_add_remove_mutator(self):
        """Test adding and removing mutators"""
        bf_val = BFUInt32(value=100)
        mut = BFMutatable(bf_val)
        mutator = BFIntegerBoundaryMutator()

        result = mut.add_mutator(mutator)
        assert result is mut
        assert mutator in mut.mutators

        result = mut.remove_mutator(mutator)
        assert result is mut
        assert mutator not in mut.mutators

    def test_traversal_order(self):
        """Test setting traversal order"""
        bf_val = BFUInt32(value=100)
        mut = BFMutatable(bf_val)

        result = mut.set_traversal_order(TraversalOrder.BFS)
        assert result is mut
        assert mut._traversal_order == TraversalOrder.BFS

    def test_simple_iteration(self):
        """Test iterating over mutations of a simple type"""
        bf_val = BFUInt8(value=42)
        mut = BFMutatable(bf_val)
        mut.add_mutator(BFIntegerBoundaryMutator())

        results = list(mut)

        assert len(results) > 0
        assert all(isinstance(r, MutationResult) for r in results)
        assert all(r.path == "" for r in results)
        assert all(r.mutator_name == "Integer Boundary Mutator" for r in results)
        assert all(len(r.packed_data) == 1 for r in results)

    def test_container_iteration(self):
        """Test iterating over mutations of a container"""
        container = BFContainer()
        container.header = BFUInt16(value=0x1234)
        container.size = BFUInt32(value=100)
        container.data = BFBuffer(b"test")

        mut = BFMutatable(container)
        mut.add_mutator(BFIntegerBoundaryMutator())
        mut.add_mutator(BFBufferLengthMutator())

        results = list(mut)

        paths = {r.path for r in results}
        assert "header" in paths
        assert "size" in paths
        assert "data" in paths

        assert all(len(r.packed_data) > 0 for r in results)

    def test_nested_container_iteration(self):
        """Test iterating over mutations of nested containers"""
        root = BFContainer()
        root.magic = BFUInt32(value=0xDEADBEEF)
        root.sub = BFContainer()
        root.sub.length = BFUInt16(value=10)
        root.sub.inner = BFContainer()
        root.sub.inner.value = BFUInt8(value=5)

        mut = BFMutatable(root)
        mut.add_mutator(BFIntegerBoundaryMutator())

        results = list(mut)
        paths = {r.path for r in results}

        assert "magic" in paths
        assert "sub.length" in paths
        assert "sub.inner.value" in paths

    def test_path_restricted_mutator(self):
        """Test mutator restricted to specific path"""
        container = BFContainer()
        container.field1 = BFUInt16(value=100)
        container.field2 = BFUInt16(value=200)

        mut = BFMutatable(container)
        mut.add_mutator(BFIntegerBoundaryMutator(), path="field1")

        results = list(mut)
        paths = {r.path for r in results}

        assert "field1" in paths
        assert "field2" not in paths

    def test_total_count(self):
        """Test total_count method"""
        bf_val = BFUInt8(value=42)
        mut = BFMutatable(bf_val)
        mut.add_mutator(BFIntegerBoundaryMutator())

        count = mut.total_count()
        actual = len(list(mut))

        assert count == actual

    def test_mutation_summary(self):
        """Test mutation summary"""
        container = BFContainer()
        container.header = BFUInt16(value=0x1234)
        container.data = BFBuffer(b"test")

        mut = BFMutatable(container)
        mut.add_mutator(BFIntegerBoundaryMutator())
        mut.add_mutator(BFBufferLengthMutator())

        summary = mut.get_mutation_summary()

        assert "total_mutators" in summary
        assert summary["total_mutators"] == 2
        assert "traversal_order" in summary
        assert "mutation_points" in summary
        assert "header" in summary["mutation_points"]
        assert "data" in summary["mutation_points"]
        assert "total_mutations" in summary

    def test_mutation_preserves_original(self):
        """Test that mutation doesn't permanently modify original"""
        bf_val = BFUInt32(value=12345)
        mut = BFMutatable(bf_val)
        mut.add_mutator(BFIntegerBoundaryMutator())

        for i, _ in enumerate(mut):
            if i > 5:
                break

        assert bf_val.value == 12345

    def test_mutation_result_has_index(self):
        """Test that MutationResult includes index"""
        bf_val = BFUInt8(value=42)
        mut = BFMutatable(bf_val)
        mut.add_mutator(BFIntegerBoundaryMutator())

        results = list(mut)

        # Check indices are sequential
        for i, result in enumerate(results):
            assert result.index == i


class TestIterationResumption:
    """Test iteration offset and limit for resumption"""

    def test_start_offset(self):
        """Test skipping mutations with start parameter"""
        bf_val = BFUInt8(value=42)
        mut = BFMutatable(bf_val)
        mut.add_mutator(BFIntegerBoundaryMutator())

        # Get all results
        all_results = list(mut.iterate_mutations())

        # Get results starting from index 3
        offset_results = list(mut.iterate_mutations(start=3))

        assert len(offset_results) == len(all_results) - 3
        assert offset_results[0].index == 3

    def test_limit(self):
        """Test limiting number of mutations"""
        bf_val = BFUInt8(value=42)
        mut = BFMutatable(bf_val)
        mut.add_mutator(BFIntegerBoundaryMutator())

        results = list(mut.iterate_mutations(limit=5))

        assert len(results) == 5
        assert results[0].index == 0
        assert results[4].index == 4

    def test_start_and_limit(self):
        """Test combining start and limit"""
        bf_val = BFUInt8(value=42)
        mut = BFMutatable(bf_val)
        mut.add_mutator(BFIntegerBoundaryMutator())

        # Get mutations 2-4 (3 total)
        results = list(mut.iterate_mutations(start=2, limit=3))

        assert len(results) == 3
        assert results[0].index == 2
        assert results[2].index == 4

    def test_parallel_splitting(self):
        """Test that we can split iterations for parallel processing"""
        container = BFContainer()
        container.a = BFUInt8(value=1)
        container.b = BFUInt8(value=2)

        mut = BFMutatable(container)
        mut.add_mutator(BFIntegerBoundaryMutator())

        total = mut.total_count()

        # Simulate 3 parallel workers
        chunk_size = total // 3

        worker1 = list(mut.iterate_mutations(start=0, limit=chunk_size))
        worker2 = list(mut.iterate_mutations(start=chunk_size, limit=chunk_size))
        worker3 = list(mut.iterate_mutations(start=chunk_size * 2))

        # All results should be covered
        all_indices = (
            [r.index for r in worker1] + [r.index for r in worker2] + [r.index for r in worker3]
        )

        assert len(all_indices) == total
        assert sorted(all_indices) == list(range(total))

    def test_resumption_scenario(self):
        """Test a real resumption scenario"""
        container = BFContainer()
        container.value = BFUInt16(value=100)

        mut = BFMutatable(container)
        mut.add_mutator(BFIntegerBoundaryMutator())

        # Simulate processing that got interrupted at index 3
        processed = []
        for result in mut.iterate_mutations():
            processed.append(result.index)
            if result.index == 2:
                # Simulate interruption
                break

        # Resume from where we left off
        resumed = list(mut.iterate_mutations(start=3))

        # Verify we can reconstruct the full sequence
        all_indices = processed + [r.index for r in resumed]
        total = mut.total_count()

        assert len(all_indices) == total


class TestBFLengthStructures:
    """Test mutators with BFLength counted structures"""

    def test_bflength_traversal(self):
        """Test that BFLength structures are properly traversed"""
        container = BFContainer()
        container.data = BFLength(BFUInt16(), BFContainer())
        container.data.payload = BFUInt32(value=0xAABBCCDD)
        container.data.extra = BFUInt8(value=10)

        mut = BFMutatable(container)
        mut.add_mutator(BFIntegerBoundaryMutator())

        results = list(mut)
        paths = {r.path for r in results}

        # Should traverse into the BFLength's data container
        assert "data.payload" in paths
        assert "data.extra" in paths

    def test_bflength_packing(self):
        """Test that mutations in BFLength still pack correctly"""
        container = BFContainer()
        container.len = BFLength(BFUInt16(), BFContainer())
        container.len.data = BFUInt32(value=0xAABBCCDD)

        mut = BFMutatable(container)
        mut.add_mutator(BFIntegerBoundaryMutator())

        for result in mut:
            # All packed data should be valid bytes
            assert isinstance(result.packed_data, bytes)
            # Length field (2) + data (varies with mutation)
            assert len(result.packed_data) >= 2


class TestComputedLengthStructures:
    """Test mutators with length_of computed-field structures"""

    def test_computed_traversal(self):
        """The computed length field and its target are both traversed."""
        container = BFContainer()
        data = BFContainer()
        data.payload = BFUInt32(value=0xAABBCCDD)
        container.length = length_of(BFUInt16(), data)
        container.data = data

        mut = BFMutatable(container)
        mut.add_mutator(BFIntegerBoundaryMutator())

        results = list(mut)
        paths = {r.path for r in results}

        # Should traverse the length field and the payload
        assert "length" in paths
        assert "data.payload" in paths

    def test_computed_packing(self):
        """Mutations of a length_of structure pack to a valid length."""
        container = BFContainer()
        data = BFContainer()
        data.payload = BFUInt32(value=0x12345678)
        container.length = length_of(BFUInt16(), data)
        container.data = data

        mut = BFMutatable(container)
        mut.add_mutator(BFIntegerBoundaryMutator())

        for result in mut:
            assert isinstance(result.packed_data, bytes)
            # Length (2) + payload (4)
            assert len(result.packed_data) == 6


class TestComputedChecksumStructures:
    """Test mutators with checksum_of computed-field structures"""

    def test_computed_traversal(self):
        """The computed checksum field and its target are both traversed."""

        def simple_checksum(data: bytes) -> int:
            return sum(data) & 0xFFFF

        container = BFContainer()
        data = BFContainer()
        data.payload = BFUInt32(value=0xAABBCCDD)
        container.checksum = checksum_of(BFUInt16(), simple_checksum, data)
        container.data = data

        mut = BFMutatable(container)
        mut.add_mutator(BFIntegerBoundaryMutator())

        results = list(mut)
        paths = {r.path for r in results}

        # Should traverse both the checksum field and the payload
        assert "checksum" in paths
        assert "data.payload" in paths

    def test_computed_packing(self):
        """Mutations of a checksum_of structure pack correctly."""

        def simple_checksum(data: bytes) -> int:
            return sum(data) & 0xFFFF

        container = BFContainer()
        data = BFContainer()
        data.value = BFUInt8(value=0x42)
        container.csum = checksum_of(BFUInt16(), simple_checksum, data)
        container.data = data

        mut = BFMutatable(container)
        mut.add_mutator(BFIntegerBoundaryMutator())

        for result in mut:
            assert isinstance(result.packed_data, bytes)


class TestTraversalOrders:
    """Test different traversal orders"""

    def setup_method(self):
        """Create a test container hierarchy"""
        self.container = BFContainer()
        self.container.a = BFUInt8(value=1)
        self.container.sub = BFContainer()
        self.container.sub.b = BFUInt8(value=2)
        self.container.sub.c = BFUInt8(value=3)
        self.container.d = BFUInt8(value=4)

    def test_dfs_preorder(self):
        """Test DFS preorder traversal"""
        mut = BFMutatable(self.container)
        mut.set_traversal_order(TraversalOrder.DFS_PREORDER)
        mut.add_mutator(BFIntegerBoundaryMutator())

        results = list(mut)
        paths = [r.path for r in results]

        first_occurrence = {}
        for i, p in enumerate(paths):
            if p not in first_occurrence:
                first_occurrence[p] = i

        assert first_occurrence["a"] < first_occurrence["sub.b"]

    def test_bfs(self):
        """Test BFS traversal"""
        mut = BFMutatable(self.container)
        mut.set_traversal_order(TraversalOrder.BFS)
        mut.add_mutator(BFIntegerBoundaryMutator())

        results = list(mut)
        paths = [r.path for r in results]

        first_occurrence = {}
        for i, p in enumerate(paths):
            if p not in first_occurrence:
                first_occurrence[p] = i

        assert first_occurrence["a"] < first_occurrence["sub.b"]
        assert first_occurrence["d"] < first_occurrence["sub.b"]


class TestConvenienceFunctions:
    """Test convenience functions"""

    def test_create_integer_mutator_suite(self):
        """Test integer mutator suite creation"""
        mutators = create_integer_mutator_suite()

        assert len(mutators) == 4
        assert any(isinstance(m, BFIntegerBoundaryMutator) for m in mutators)
        assert any(isinstance(m, BFIntegerSignMutator) for m in mutators)
        assert any(isinstance(m, BFIntegerSpecialValueMutator) for m in mutators)
        assert any(isinstance(m, BFIntegerBitPatternMutator) for m in mutators)

    def test_create_buffer_mutator_suite(self):
        """Test buffer mutator suite creation"""
        mutators = create_buffer_mutator_suite()

        assert len(mutators) == 3
        assert any(isinstance(m, BFBufferLengthMutator) for m in mutators)
        assert any(isinstance(m, BFBufferContentMutator) for m in mutators)
        assert any(isinstance(m, BFBufferNullTerminationMutator) for m in mutators)

    def test_create_full_mutator_suite(self):
        """Test full mutator suite creation"""
        mutators = create_full_mutator_suite()

        assert len(mutators) == 7  # 4 integer + 3 buffer

    def test_mutate_function(self):
        """Test convenience mutate function"""
        container = BFContainer()
        container.value = BFUInt16(value=100)
        container.data = BFBuffer(b"test")

        results = list(mutate(container))

        assert len(results) > 0
        paths = {r.path for r in results}
        assert "value" in paths
        assert "data" in paths

    def test_mutate_with_custom_mutators(self):
        """Test mutate function with custom mutator list"""
        bf_val = BFUInt32(value=100)

        results = list(mutate(bf_val, mutators=[BFIntegerBoundaryMutator()]))

        assert all(r.mutator_name == "Integer Boundary Mutator" for r in results)

    def test_mutate_with_traversal_order(self):
        """Test mutate function with traversal order"""
        container = BFContainer()
        container.a = BFUInt8(value=1)
        container.b = BFUInt8(value=2)

        results_dfs = list(mutate(container, order=TraversalOrder.DFS_PREORDER))
        results_bfs = list(mutate(container, order=TraversalOrder.BFS))

        assert len(results_dfs) > 0
        assert len(results_bfs) > 0

    def test_mutate_with_start_limit(self):
        """Test mutate function with start and limit"""
        bf_val = BFUInt8(value=42)

        results = list(mutate(bf_val, start=2, limit=3))

        assert len(results) == 3
        assert results[0].index == 2


class TestMutationResult:
    """Test MutationResult dataclass"""

    def test_mutation_result_fields(self):
        """Test that MutationResult has all expected fields"""
        result = MutationResult(
            index=42,
            path="test.field",
            original_value=100,
            mutated_value=255,
            mutator_name="Test Mutator",
            metadata={"references": [{"source": "CWE", "id": "190"}], "tags": ["test"]},
            description="Overflow test",
            packed_data=b"\xff",
        )

        assert result.index == 42
        assert result.path == "test.field"
        assert result.original_value == 100
        assert result.mutated_value == 255
        assert result.mutator_name == "Test Mutator"
        assert "references" in result.metadata
        assert result.description == "Overflow test"
        assert result.packed_data == b"\xff"


class TestIntegration:
    """Integration tests for the mutation system"""

    def test_full_packet_mutation(self):
        """Test mutating a complete packet structure"""
        packet = BFContainer()
        packet.magic = BFUInt32(value=0x12345678)
        packet.version = BFUInt8(value=1)
        packet.flags = BFUInt16(value=0)
        packet.payload_len = BFUInt32(value=4)
        packet.payload = BFBuffer(b"\x00\x00\x00\x00")

        mut = BFMutatable(packet)
        for m in create_full_mutator_suite():
            mut.add_mutator(m)

        count = 0
        for result in mut:
            count += 1
            assert isinstance(result.packed_data, bytes)
            assert len(result.packed_data) > 0

        assert count > 50

    def test_metadata_coverage(self):
        """Test that mutations include appropriate metadata"""
        container = BFContainer()
        container.num = BFUInt32(value=100)
        container.buf = BFBuffer(b"test")

        mut = BFMutatable(container)
        for m in create_full_mutator_suite():
            mut.add_mutator(m)

        # Collect all sources from metadata
        all_sources = set()
        for result in mut:
            for ref in result.metadata.get("references", []):
                all_sources.add(ref["source"])

        assert "CWE" in all_sources

    def test_generator_behavior(self):
        """Test that iteration is truly lazy (generator)"""
        bf_val = BFUInt32(value=100)
        mut = BFMutatable(bf_val)
        mut.add_mutator(BFIntegerBoundaryMutator())

        iterator = iter(mut)

        result1 = next(iterator)
        result2 = next(iterator)

        assert result1 is not result2
        assert isinstance(result1, MutationResult)
        assert isinstance(result2, MutationResult)

    def test_complex_nested_with_length(self):
        """Test complex structure with BFLength"""
        packet = BFContainer()
        packet.header = BFContainer()
        packet.header.magic = BFUInt32(value=0xDEADBEEF)
        packet.header.version = BFUInt8(value=1)
        packet.body = BFLength(BFUInt16(), BFContainer())
        packet.body.data = BFBuffer(b"Hello World")
        packet.body.checksum = BFUInt32(value=0)

        mut = BFMutatable(packet)
        mut.add_mutator(BFIntegerBoundaryMutator())
        mut.add_mutator(BFBufferLengthMutator())

        results = list(mut)
        paths = {r.path for r in results}

        assert "header.magic" in paths
        assert "header.version" in paths
        assert "body.data" in paths
        assert "body.checksum" in paths
