# pylint: disable=too-few-public-methods
"""BitFactory Mutators test suite"""
import pytest

from bitfactory import (
    BFBuffer,
    BFContainer,
    BFSInt8,
    BFSInt16,
    BFSInt32,
    BFUInt8,
    BFUInt16,
    BFUInt32,
)
from bitfactory.mutators import (
    BFBufferContentMutator,
    BFBufferLengthMutator,
    BFBufferNullTerminationMutator,
    BFIntegerBitPatternMutator,
    BFIntegerBoundaryMutator,
    BFIntegerSignMutator,
    BFIntegerSpecialValueMutator,
    BFMutatable,
    BFMutator,
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


class TestBFIntegerBoundaryMutator:
    """Test integer boundary mutator"""

    def test_properties(self):
        """Test mutator properties"""
        mutator = BFIntegerBoundaryMutator()
        assert mutator.name == "Integer Boundary Mutator"
        assert "CWE-190" in mutator.cwe_ids
        assert "CWE-191" in mutator.cwe_ids
        assert BFUInt8 in mutator.supported_types
        assert BFSInt32 in mutator.supported_types

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

        # Should include max/min values
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
        assert "CWE-194" in mutator.cwe_ids
        assert "CWE-195" in mutator.cwe_ids

    def test_sign_bit_values(self):
        """Test that sign bit mutations are generated"""
        mutator = BFIntegerSignMutator()
        bf_val = BFUInt8(value=0)

        mutations = list(mutator.mutate(bf_val))
        values = [m[0] for m in mutations]

        # Should have sign bit set value
        assert 0x80 in values
        assert 0x7F in values  # All bits except sign

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
        assert "CWE-369" in mutator.cwe_ids  # Divide by zero
        assert "CWE-682" in mutator.cwe_ids

    def test_special_values(self):
        """Test special value mutations"""
        mutator = BFIntegerSpecialValueMutator()
        bf_val = BFUInt16(value=100)

        mutations = list(mutator.mutate(bf_val))
        values = [m[0] for m in mutations]

        # Zero for divide-by-zero
        assert 0 in values
        # One for off-by-one
        assert 1 in values
        # Powers of two
        assert 4 in values
        assert 16 in values
        assert 256 in values


class TestBFIntegerBitPatternMutator:
    """Test integer bit pattern mutator"""

    def test_properties(self):
        """Test mutator properties"""
        mutator = BFIntegerBitPatternMutator()
        assert "CWE-704" in mutator.cwe_ids

    def test_bit_patterns_uint8(self):
        """Test bit pattern mutations for 8-bit"""
        mutator = BFIntegerBitPatternMutator()
        bf_val = BFUInt8(value=0)

        mutations = list(mutator.mutate(bf_val))
        values = [m[0] for m in mutations]

        assert 0xFF in values  # All bits set
        assert 0xAA in values  # Alternating 10101010
        assert 0x55 in values  # Alternating 01010101
        assert 1 in values  # Single bit 0
        assert 2 in values  # Single bit 1
        assert 0x0F in values  # Low nibble

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


class TestBFBufferLengthMutator:
    """Test buffer length mutator"""

    def test_properties(self):
        """Test mutator properties"""
        mutator = BFBufferLengthMutator()
        assert "CWE-120" in mutator.cwe_ids
        assert "CWE-787" in mutator.cwe_ids
        assert BFBuffer in mutator.supported_types

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

        # Check for empty buffer
        assert any(m[0] == b"" for m in mutations)
        # Check for single byte
        assert any(m[0] == b"\x00" for m in mutations)
        # Check for various boundary sizes
        lengths = [len(m[0]) for m in mutations]
        assert 1 in lengths
        assert 256 in lengths


class TestBFBufferContentMutator:
    """Test buffer content mutator"""

    def test_properties(self):
        """Test mutator properties"""
        mutator = BFBufferContentMutator()
        assert "CWE-134" in mutator.cwe_ids  # Format string
        assert "CWE-78" in mutator.cwe_ids  # Command injection

    def test_content_mutations(self):
        """Test buffer content mutations"""
        mutator = BFBufferContentMutator()
        bf_val = BFBuffer(b"test")

        mutations = list(mutator.mutate(bf_val))
        values = [m[0] for m in mutations]

        # Check for format string patterns
        assert any(b"%s" in v for v in values)
        assert any(b"%n" in v for v in values)

        # Check for all nulls
        assert any(v == b"\x00" * 16 for v in values)

        # Check for path traversal
        assert any(b"/../" in v for v in values)


class TestBFBufferNullTerminationMutator:
    """Test buffer null termination mutator"""

    def test_properties(self):
        """Test mutator properties"""
        mutator = BFBufferNullTerminationMutator()
        assert "CWE-170" in mutator.cwe_ids
        assert "CWE-126" in mutator.cwe_ids

    def test_null_mutations(self):
        """Test null termination mutations"""
        mutator = BFBufferNullTerminationMutator()
        bf_val = BFBuffer(b"hello\x00")

        mutations = list(mutator.mutate(bf_val))
        values = [m[0] for m in mutations]

        # Should have version without null terminator
        assert b"hello" in values

        # Should have multiple null terminators
        assert any(v.endswith(b"\x00\x00\x00") for v in values)

        # Should have data after null
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

        # Add
        result = mut.add_mutator(mutator)
        assert result is mut  # Method chaining
        assert mutator in mut.mutators

        # Remove
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
        assert all(r.path == "" for r in results)  # Single value, no path
        assert all(r.mutator_name == "Integer Boundary Mutator" for r in results)
        assert all(len(r.packed_data) == 1 for r in results)  # UInt8 = 1 byte

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

        # Should have mutations from both header, size (int), and data (buffer)
        paths = set(r.path for r in results)
        assert "header" in paths
        assert "size" in paths
        assert "data" in paths

        # All results should have packed data
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
        paths = set(r.path for r in results)

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
        paths = set(r.path for r in results)

        # Should only mutate field1
        assert "field1" in paths
        assert "field2" not in paths

    def test_count_mutations(self):
        """Test counting mutations"""
        bf_val = BFUInt8(value=42)
        mut = BFMutatable(bf_val)
        mut.add_mutator(BFIntegerBoundaryMutator())

        count = mut.count_mutations()
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

    def test_mutation_preserves_original(self):
        """Test that mutation doesn't permanently modify original"""
        bf_val = BFUInt32(value=12345)
        mut = BFMutatable(bf_val)
        mut.add_mutator(BFIntegerBoundaryMutator())

        # Iterate through some mutations
        for i, _ in enumerate(mut):
            if i > 5:
                break

        # Original should be unchanged
        assert bf_val.value == 12345


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

        # Should see nodes in depth-first order
        # First occurrence of each path
        first_occurrence = {}
        for i, p in enumerate(paths):
            if p not in first_occurrence:
                first_occurrence[p] = i

        # a should come before sub.b and sub.c
        assert first_occurrence["a"] < first_occurrence["sub.b"]

    def test_bfs(self):
        """Test BFS traversal"""
        mut = BFMutatable(self.container)
        mut.set_traversal_order(TraversalOrder.BFS)
        mut.add_mutator(BFIntegerBoundaryMutator())

        results = list(mut)
        paths = [r.path for r in results]

        # First occurrence of each path
        first_occurrence = {}
        for i, p in enumerate(paths):
            if p not in first_occurrence:
                first_occurrence[p] = i

        # In BFS, all top-level should come before nested
        # a and d should come before sub.b and sub.c
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
        paths = set(r.path for r in results)
        assert "value" in paths
        assert "data" in paths

    def test_mutate_with_custom_mutators(self):
        """Test mutate function with custom mutator list"""
        bf_val = BFUInt32(value=100)

        # Use only boundary mutator
        results = list(mutate(bf_val, mutators=[BFIntegerBoundaryMutator()]))

        assert all(r.mutator_name == "Integer Boundary Mutator" for r in results)

    def test_mutate_with_traversal_order(self):
        """Test mutate function with traversal order"""
        container = BFContainer()
        container.a = BFUInt8(value=1)
        container.b = BFUInt8(value=2)

        # Should work with different orders
        results_dfs = list(mutate(container, order=TraversalOrder.DFS_PREORDER))
        results_bfs = list(mutate(container, order=TraversalOrder.BFS))

        assert len(results_dfs) > 0
        assert len(results_bfs) > 0


class TestMutationResult:
    """Test MutationResult dataclass"""

    def test_mutation_result_fields(self):
        """Test that MutationResult has all expected fields"""
        result = MutationResult(
            path="test.field",
            original_value=100,
            mutated_value=255,
            mutator_name="Test Mutator",
            cwe_ids=["CWE-190"],
            description="Overflow test",
            packed_data=b"\xff",
        )

        assert result.path == "test.field"
        assert result.original_value == 100
        assert result.mutated_value == 255
        assert result.mutator_name == "Test Mutator"
        assert "CWE-190" in result.cwe_ids
        assert result.description == "Overflow test"
        assert result.packed_data == b"\xff"


class TestIntegration:
    """Integration tests for the mutation system"""

    def test_full_packet_mutation(self):
        """Test mutating a complete packet structure"""
        # Create a packet-like structure
        packet = BFContainer()
        packet.magic = BFUInt32(value=0x12345678)
        packet.version = BFUInt8(value=1)
        packet.flags = BFUInt16(value=0)
        packet.payload_len = BFUInt32(value=4)
        packet.payload = BFBuffer(b"\x00\x00\x00\x00")

        mut = BFMutatable(packet)
        for m in create_full_mutator_suite():
            mut.add_mutator(m)

        # Count mutations
        count = 0
        for result in mut:
            count += 1
            # Verify each result has valid packed data
            assert isinstance(result.packed_data, bytes)
            assert len(result.packed_data) > 0

        assert count > 50  # Should have many mutations

    def test_cwe_coverage(self):
        """Test that mutations cover expected CWEs"""
        container = BFContainer()
        container.num = BFUInt32(value=100)
        container.buf = BFBuffer(b"test")

        mut = BFMutatable(container)
        for m in create_full_mutator_suite():
            mut.add_mutator(m)

        # Collect all CWE IDs from mutations
        all_cwes = set()
        for result in mut:
            all_cwes.update(result.cwe_ids)

        # Should cover important CWEs
        assert "CWE-190" in all_cwes  # Integer overflow
        assert "CWE-191" in all_cwes  # Integer underflow
        assert "CWE-120" in all_cwes  # Buffer overflow
        assert "CWE-369" in all_cwes  # Divide by zero
        assert "CWE-134" in all_cwes  # Format string

    def test_generator_behavior(self):
        """Test that iteration is truly lazy (generator)"""
        bf_val = BFUInt32(value=100)
        mut = BFMutatable(bf_val)
        mut.add_mutator(BFIntegerBoundaryMutator())

        # Get iterator
        iterator = iter(mut)

        # Should be able to get items one at a time
        result1 = next(iterator)
        result2 = next(iterator)

        assert result1 is not result2
        assert isinstance(result1, MutationResult)
        assert isinstance(result2, MutationResult)
