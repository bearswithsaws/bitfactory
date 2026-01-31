"""BitFactory Mutators Module

This module provides a mutation system for BitFactory types that enables
systematic generation of edge-case and potentially invalid values for
security testing, fuzzing, and protocol validation.

Mutators can be attached to any BF type at any level in a hierarchy,
and the system supports recursive iteration with configurable traversal
orders (BFS, DFS preorder, DFS postorder).

Metadata System:
    Mutators provide metadata describing the test cases they generate.
    This is flexible and can include references to various standards:
    - CWE (Common Weakness Enumeration)
    - OWASP categories
    - Custom tags and descriptions

    Example metadata:
        {
            "references": [
                {"source": "CWE", "id": "190", "name": "Integer Overflow"},
                {"source": "OWASP", "id": "A03", "name": "Injection"},
            ],
            "tags": ["boundary", "overflow", "integer"],
            "category": "integer-arithmetic",
        }
"""

import abc
from collections import deque
from collections.abc import Generator
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Optional

from .bitfactory import (
    BFBasicDataType,
    BFBuffer,
    BFCallableRef,
    BFContainer,
    BFLength,
    BFLengthRef,
    BFSInt8,
    BFSInt16,
    BFSInt32,
    BFUInt8,
    BFUInt16,
    BFUInt32,
)


class TraversalOrder(Enum):
    """Defines the order in which mutator nodes are evaluated during iteration.

    Attributes:
        DFS_PREORDER: Depth-first, process node before children (root first)
        DFS_POSTORDER: Depth-first, process node after children (leaves first)
        BFS: Breadth-first, process level by level
    """

    DFS_PREORDER = auto()
    DFS_POSTORDER = auto()
    BFS = auto()


@dataclass
class MutationResult:
    """Represents a single mutation result.

    Attributes:
        index: The zero-based index of this mutation in the sequence
        path: Dot-separated path to the mutated field (e.g., "header.length")
        original_value: The original value before mutation
        mutated_value: The mutated value
        mutator_name: Name of the mutator that produced this value
        metadata: Flexible metadata dict (references, tags, category, etc.)
        description: Human-readable description of the mutation
        packed_data: The full packed binary data with the mutation applied
    """

    index: int
    path: str
    original_value: Any
    mutated_value: Any
    mutator_name: str
    metadata: dict[str, Any]
    description: str
    packed_data: bytes = b""


@dataclass
class MutatorBinding:
    """Binds a mutator to a specific path in the type hierarchy.

    Attributes:
        mutator: The mutator instance
        path: Optional path restriction (None means apply to matching types anywhere)
    """

    mutator: "BFMutator"
    path: Optional[str] = None


class BFMutator(abc.ABC):
    """Abstract base class for all BitFactory mutators.

    Mutators generate sequences of values designed to test edge cases,
    boundary conditions, and potentially invalid states.

    Subclasses must implement the `mutate` method and specify which
    BF types they can mutate via `supported_types`.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable name for this mutator."""

    @property
    @abc.abstractmethod
    def metadata(self) -> dict[str, Any]:
        """Metadata describing this mutator's test cases.

        Returns a dict that may contain:
        - references: List of dicts with 'source', 'id', and optionally 'name'
        - tags: List of string tags
        - category: String category name
        - description: Detailed description

        Example:
            {
                "references": [
                    {"source": "CWE", "id": "190", "name": "Integer Overflow"},
                ],
                "tags": ["boundary", "overflow"],
                "category": "integer-arithmetic",
            }
        """

    @property
    @abc.abstractmethod
    def supported_types(self) -> tuple[type, ...]:
        """Tuple of BFBasicDataType subclasses this mutator can handle."""

    def can_mutate(self, bf_type: BFBasicDataType) -> bool:
        """Check if this mutator can handle the given type.

        Args:
            bf_type: A BitFactory type instance

        Returns:
            True if this mutator supports the type
        """
        return isinstance(bf_type, self.supported_types)

    @abc.abstractmethod
    def mutate(self, bf_type: BFBasicDataType) -> Generator[tuple[Any, str], None, None]:
        """Generate mutated values for the given type.

        Args:
            bf_type: A BitFactory type instance to mutate

        Yields:
            Tuple of (mutated_value, description) for each mutation
        """


def _make_cwe_ref(cwe_id: str, name: str = "") -> dict[str, str]:
    """Helper to create a CWE reference entry."""
    ref = {"source": "CWE", "id": cwe_id}
    if name:
        ref["name"] = name
    return ref


# =============================================================================
# Integer Mutators - Boundary and edge case testing
# =============================================================================


class BFIntegerBoundaryMutator(BFMutator):
    """Generates integer boundary values to test overflow/underflow conditions.

    This mutator produces values at and around the boundaries of integer
    types, targeting vulnerabilities like integer overflow and wraparound.
    """

    @property
    def name(self) -> str:
        return "Integer Boundary Mutator"

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "references": [
                _make_cwe_ref("190", "Integer Overflow or Wraparound"),
                _make_cwe_ref("191", "Integer Underflow or Wraparound"),
                _make_cwe_ref("128", "Wrap-around Error"),
            ],
            "tags": ["boundary", "overflow", "underflow", "integer"],
            "category": "integer-arithmetic",
        }

    @property
    def supported_types(self) -> tuple[type, ...]:
        return (BFUInt8, BFSInt8, BFUInt16, BFSInt16, BFUInt32, BFSInt32)

    def _get_boundaries(self, bf_type: BFBasicDataType) -> Generator[tuple[int, str], None, None]:
        """Generate boundary values based on type."""
        is_signed = isinstance(bf_type, (BFSInt8, BFSInt16, BFSInt32))

        if isinstance(bf_type, (BFUInt8, BFSInt8)):
            bits = 8
        elif isinstance(bf_type, (BFUInt16, BFSInt16)):
            bits = 16
        elif isinstance(bf_type, (BFUInt32, BFSInt32)):
            bits = 32
        else:
            return

        if is_signed:
            max_val = (1 << (bits - 1)) - 1
            min_val = -(1 << (bits - 1))
            unsigned_max = (1 << bits) - 1

            yield (max_val, f"MAX_SIGNED_{bits} ({max_val})")
            yield (max_val + 1, f"MAX_SIGNED_{bits}+1 overflow ({max_val + 1})")
            yield (min_val, f"MIN_SIGNED_{bits} ({min_val})")
            yield (min_val - 1, f"MIN_SIGNED_{bits}-1 underflow ({min_val - 1})")
            yield (0, "Zero")
            yield (-1, "Negative one")
            yield (1, "One")
            yield (unsigned_max, f"MAX_UNSIGNED_{bits} as signed ({unsigned_max})")
        else:
            max_val = (1 << bits) - 1
            min_val = 0

            yield (max_val, f"MAX_UNSIGNED_{bits} ({max_val})")
            yield (max_val + 1, f"MAX_UNSIGNED_{bits}+1 overflow ({max_val + 1})")
            yield (min_val, f"MIN_UNSIGNED_{bits} (0)")
            yield (min_val - 1, f"MIN_UNSIGNED_{bits}-1 underflow (-1)")
            yield (1, "One")
            yield (max_val // 2, f"HALF_MAX_{bits} ({max_val // 2})")
            yield ((max_val // 2) + 1, f"HALF_MAX_{bits}+1 ({(max_val // 2) + 1})")

    def mutate(self, bf_type: BFBasicDataType) -> Generator[tuple[Any, str], None, None]:
        if not self.can_mutate(bf_type):
            return

        yield from self._get_boundaries(bf_type)


class BFIntegerSignMutator(BFMutator):
    """Tests sign-related integer vulnerabilities."""

    @property
    def name(self) -> str:
        return "Integer Sign Mutator"

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "references": [
                _make_cwe_ref("194", "Unexpected Sign Extension"),
                _make_cwe_ref("195", "Signed to Unsigned Conversion Error"),
                _make_cwe_ref("196", "Unsigned to Signed Conversion Error"),
            ],
            "tags": ["sign", "conversion", "integer"],
            "category": "integer-conversion",
        }

    @property
    def supported_types(self) -> tuple[type, ...]:
        return (BFUInt8, BFSInt8, BFUInt16, BFSInt16, BFUInt32, BFSInt32)

    def mutate(self, bf_type: BFBasicDataType) -> Generator[tuple[Any, str], None, None]:
        if not self.can_mutate(bf_type):
            return

        is_signed = isinstance(bf_type, (BFSInt8, BFSInt16, BFSInt32))

        if isinstance(bf_type, (BFUInt8, BFSInt8)):
            bits = 8
        elif isinstance(bf_type, (BFUInt16, BFSInt16)):
            bits = 16
        else:
            bits = 32

        sign_bit_set = 1 << (bits - 1)
        yield (sign_bit_set, f"Sign bit set (0x{sign_bit_set:X})")

        all_except_sign = (1 << (bits - 1)) - 1
        yield (all_except_sign, f"All bits except sign (0x{all_except_sign:X})")

        if is_signed:
            yield (-1, "Negative one (0xFF... when cast to unsigned)")
            yield (-(1 << (bits - 2)), f"Large negative (-{1 << (bits - 2)})")
        else:
            signed_max = (1 << (bits - 1)) - 1
            yield (signed_max + 1, f"Signed overflow when cast (0x{signed_max + 1:X})")
            yield ((1 << bits) - 1, f"All bits set - becomes -1 signed (0x{(1 << bits) - 1:X})")

        if bits > 8:
            yield (0x80, "0x80 - sign extends in smaller type")
            yield (0x7F, "0x7F - max positive in smaller type")
            if bits > 16:
                yield (0x8000, "0x8000 - sign extends from 16-bit")
                yield (0x7FFF, "0x7FFF - max positive 16-bit")


class BFIntegerSpecialValueMutator(BFMutator):
    """Generates special integer values that often cause issues."""

    @property
    def name(self) -> str:
        return "Integer Special Value Mutator"

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "references": [
                _make_cwe_ref("369", "Divide By Zero"),
                _make_cwe_ref("682", "Incorrect Calculation"),
                _make_cwe_ref("681", "Incorrect Conversion between Numeric Types"),
            ],
            "tags": ["special-value", "divide-by-zero", "integer"],
            "category": "integer-arithmetic",
        }

    @property
    def supported_types(self) -> tuple[type, ...]:
        return (BFUInt8, BFSInt8, BFUInt16, BFSInt16, BFUInt32, BFSInt32)

    def mutate(self, bf_type: BFBasicDataType) -> Generator[tuple[Any, str], None, None]:
        if not self.can_mutate(bf_type):
            return

        yield (0, "Zero (potential divide-by-zero)")
        yield (1, "One (off-by-one boundary)")

        if isinstance(bf_type, (BFUInt8, BFSInt8)):
            max_power = 7
        elif isinstance(bf_type, (BFUInt16, BFSInt16)):
            max_power = 15
        else:
            max_power = 31

        for power in [2, 4, 8, 16]:
            if power <= max_power:
                val = 1 << power
                yield (val, f"Power of 2: 2^{power} = {val}")
                yield (val - 1, f"Power of 2 minus 1: 2^{power}-1 = {val - 1}")
                yield (val + 1, f"Power of 2 plus 1: 2^{power}+1 = {val + 1}")

        common_sizes = [
            (64, "Common block size"),
            (128, "Common buffer size"),
            (256, "Byte overflow boundary"),
            (512, "Common sector size"),
            (1024, "1KB boundary"),
            (4096, "Common page size"),
            (65535, "16-bit max"),
            (65536, "16-bit overflow"),
        ]

        if isinstance(bf_type, (BFUInt8, BFSInt8)):
            bits = 8
        elif isinstance(bf_type, (BFUInt16, BFSInt16)):
            bits = 16
        else:
            bits = 32

        max_val = (1 << bits) - 1
        for val, desc in common_sizes:
            if val <= max_val + 1:
                yield (val, desc)


class BFIntegerBitPatternMutator(BFMutator):
    """Generates interesting bit patterns for testing."""

    @property
    def name(self) -> str:
        return "Integer Bit Pattern Mutator"

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "references": [
                _make_cwe_ref("704", "Incorrect Type Conversion or Cast"),
                _make_cwe_ref("188", "Reliance on Data/Memory Layout"),
            ],
            "tags": ["bit-pattern", "memory-layout", "integer"],
            "category": "bit-manipulation",
        }

    @property
    def supported_types(self) -> tuple[type, ...]:
        return (BFUInt8, BFSInt8, BFUInt16, BFSInt16, BFUInt32, BFSInt32)

    def mutate(self, bf_type: BFBasicDataType) -> Generator[tuple[Any, str], None, None]:
        if not self.can_mutate(bf_type):
            return

        if isinstance(bf_type, (BFUInt8, BFSInt8)):
            bits = 8
        elif isinstance(bf_type, (BFUInt16, BFSInt16)):
            bits = 16
        else:
            bits = 32

        all_ones = (1 << bits) - 1
        yield (all_ones, f"All bits set (0x{all_ones:X})")

        if bits == 8:
            yield (0xAA, "Alternating bits 10101010")
            yield (0x55, "Alternating bits 01010101")
        elif bits == 16:
            yield (0xAAAA, "Alternating bits 1010...")
            yield (0x5555, "Alternating bits 0101...")
        else:
            yield (0xAAAAAAAA, "Alternating bits 1010...")
            yield (0x55555555, "Alternating bits 0101...")

        for i in range(min(bits, 8)):
            val = 1 << i
            yield (val, f"Single bit {i} set (0x{val:X})")

        if bits > 8:
            for i in [bits - 1, bits - 2, bits // 2]:
                val = 1 << i
                yield (val, f"Bit {i} set (0x{val:X})")

        if bits >= 8:
            yield (0x0F, "Low nibble set")
            yield (0xF0, "High nibble of byte set")
        if bits >= 16:
            yield (0x00FF, "Low byte set")
            yield (0xFF00, "High byte of word set")
        if bits >= 32:
            yield (0x0000FFFF, "Low word set")
            yield (0xFFFF0000, "High word set")


class BFBitFlipMutator(BFMutator):
    """Flips individual bits in the value, one at a time.

    For an 8-bit value, generates 8 mutations (one per bit).
    For a 32-bit value, generates 32 mutations.
    For buffers, generates len(buffer) * 8 mutations.

    This is a non-CWE-based mutator useful for general fuzzing
    and fault injection testing.
    """

    @property
    def name(self) -> str:
        return "Bit Flip Mutator"

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "tags": ["bit-flip", "fuzzing", "fault-injection"],
            "category": "bit-manipulation",
            "description": "Flips each bit individually to test error handling",
        }

    @property
    def supported_types(self) -> tuple[type, ...]:
        return (BFUInt8, BFSInt8, BFUInt16, BFSInt16, BFUInt32, BFSInt32, BFBuffer)

    def mutate(self, bf_type: BFBasicDataType) -> Generator[tuple[Any, str], None, None]:
        if not self.can_mutate(bf_type):
            return

        if isinstance(bf_type, BFBuffer):
            # For buffers, flip each bit in each byte
            original = bf_type.value
            for byte_idx in range(len(original)):
                for bit_idx in range(8):
                    # Create a copy with one bit flipped
                    mutated = bytearray(original)
                    mutated[byte_idx] ^= 1 << bit_idx
                    yield (
                        bytes(mutated),
                        f"Flip bit {bit_idx} of byte {byte_idx} "
                        f"(0x{original[byte_idx]:02X} -> 0x{mutated[byte_idx]:02X})",
                    )
        else:
            # For integers, determine bit width
            if isinstance(bf_type, (BFUInt8, BFSInt8)):
                bits = 8
            elif isinstance(bf_type, (BFUInt16, BFSInt16)):
                bits = 16
            else:
                bits = 32

            original = bf_type.value
            for bit_idx in range(bits):
                mutated = original ^ (1 << bit_idx)
                yield (
                    mutated,
                    f"Flip bit {bit_idx} (0x{original:X} -> 0x{mutated & ((1 << bits) - 1):X})",
                )


# =============================================================================
# Buffer Mutators
# =============================================================================


class BFBufferLengthMutator(BFMutator):
    """Generates buffer length edge cases."""

    @property
    def name(self) -> str:
        return "Buffer Length Mutator"

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "references": [
                _make_cwe_ref("120", "Buffer Copy without Checking Size"),
                _make_cwe_ref("787", "Out-of-bounds Write"),
                _make_cwe_ref("125", "Out-of-bounds Read"),
                _make_cwe_ref("131", "Incorrect Calculation of Buffer Size"),
            ],
            "tags": ["buffer", "length", "overflow"],
            "category": "buffer-handling",
        }

    @property
    def supported_types(self) -> tuple[type, ...]:
        return (BFBuffer,)

    def __init__(self, length_variations: Optional[list[int]] = None):
        """Initialize with optional custom length variations.

        Args:
            length_variations: List of length adjustments to apply
        """
        self._length_variations = length_variations or [
            -1,
            0,
            1,
            2,
            -2,
            255,
            256,
            1024,
            4096,
            65535,
            65536,
        ]

    def mutate(self, bf_type: BFBasicDataType) -> Generator[tuple[Any, str], None, None]:
        if not self.can_mutate(bf_type):
            return

        original_len = len(bf_type.value)

        yield (b"", "Empty buffer (length=0)")
        yield (b"\x00", "Single null byte")
        yield (b"\xff", "Single 0xFF byte")

        for delta in self._length_variations:
            new_len = original_len + delta
            if new_len > 0 and new_len != original_len:
                if new_len > original_len:
                    new_data = bf_type.value + (b"\x41" * (new_len - original_len))
                else:
                    new_data = bf_type.value[:new_len]
                yield (new_data, f"Length {original_len} -> {new_len} (delta={delta:+d})")

        boundary_sizes = [1, 2, 4, 8, 16, 32, 64, 128, 255, 256, 512, 1024, 4096]
        for size in boundary_sizes:
            if size != original_len:
                data = b"\x42" * size
                yield (data, f"Boundary size {size} bytes")


class BFBufferContentMutator(BFMutator):
    """Generates buffers with special content patterns."""

    @property
    def name(self) -> str:
        return "Buffer Content Mutator"

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "references": [
                _make_cwe_ref("134", "Use of Externally-Controlled Format String"),
                _make_cwe_ref("78", "OS Command Injection"),
                _make_cwe_ref("89", "SQL Injection"),
                _make_cwe_ref("79", "XSS"),
            ],
            "tags": ["buffer", "content", "injection"],
            "category": "injection-testing",
        }

    @property
    def supported_types(self) -> tuple[type, ...]:
        return (BFBuffer,)

    def mutate(self, bf_type: BFBasicDataType) -> Generator[tuple[Any, str], None, None]:
        if not self.can_mutate(bf_type):
            return

        original_len = max(len(bf_type.value), 16)

        yield (b"\x00" * original_len, "All null bytes")
        yield (
            bf_type.value[:1] + b"\x00" + bf_type.value[2:] if len(bf_type.value) > 2 else b"\x00",
            "Embedded null byte",
        )

        yield (b"\xff" * original_len, "All 0xFF bytes")
        yield (b"\x80" * original_len, "All 0x80 bytes (high bit set)")

        format_patterns = [
            b"%s%s%s%s%s",
            b"%n%n%n%n%n",
            b"%x%x%x%x%x",
            b"AAAA%08x.%08x.%08x.%08x",
            b"%p%p%p%p%p",
        ]
        for pattern in format_patterns:
            yield (pattern, f"Format string: {pattern[:20]}")

        yield (b"A" * 1024, "Long A pattern (1024 bytes)")
        yield (b"A" * 4096, "Long A pattern (4096 bytes)")
        yield (bytes(range(256)), "All byte values 0x00-0xFF")
        yield (b"\r\n" * 100, "CRLF repetition")
        yield (b"/../" * 50, "Path traversal pattern")


class BFBufferNullTerminationMutator(BFMutator):
    """Tests null termination handling in buffers."""

    @property
    def name(self) -> str:
        return "Buffer Null Termination Mutator"

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "references": [
                _make_cwe_ref("170", "Improper Null Termination"),
                _make_cwe_ref("126", "Buffer Over-read"),
            ],
            "tags": ["buffer", "null-termination", "string"],
            "category": "string-handling",
        }

    @property
    def supported_types(self) -> tuple[type, ...]:
        return (BFBuffer,)

    def mutate(self, bf_type: BFBasicDataType) -> Generator[tuple[Any, str], None, None]:
        if not self.can_mutate(bf_type):
            return

        original = bf_type.value
        length = len(original)

        if original.endswith(b"\x00"):
            yield (original[:-1], "Removed null terminator")
        else:
            yield (original + b"A" * 10, "Extended without null terminator")

        yield (original + b"\x00\x00\x00", "Multiple null terminators")

        if length > 2:
            mid = length // 2
            yield (original[:mid] + b"\x00" + original[mid + 1 :], "Null in middle")

        yield (b"\x00" + original[1:] if length > 0 else b"\x00", "Null at start")
        yield (b"AAAA\x00BBBB", "Data after null terminator")


# =============================================================================
# Mutatable Wrapper - Makes any BF type iterable with mutations
# =============================================================================


class BFMutatable:
    """Wrapper that adds mutation capabilities to any BitFactory structure.

    This class wraps a BFBasicDataType (including BFContainer hierarchies)
    and provides iteration over all possible mutations based on attached
    mutators.

    Supports:
    - Iteration offset and limit for resumption and parallelization
    - Multiple traversal orders (BFS, DFS)
    - Path-restricted mutators
    - BFLength, BFLengthRef, and BFCallableRef structures

    Example:
        >>> container = BFContainer()
        >>> container.header = BFUInt32(value=100)
        >>> container.data = BFBuffer(b"test")
        >>>
        >>> mut = BFMutatable(container)
        >>> mut.add_mutator(BFIntegerBoundaryMutator())
        >>>
        >>> # Get total count for progress tracking
        >>> total = mut.total_count()
        >>>
        >>> # Iterate with offset for resumption
        >>> for result in mut.iterate_mutations(start=100, limit=50):
        ...     print(f"[{result.index}] {result.path}: {result.description}")
    """

    def __init__(self, bf_type: BFBasicDataType):
        """Initialize with a BitFactory type.

        Args:
            bf_type: Any BFBasicDataType instance (including containers)
        """
        self._root = bf_type
        self._mutators: list[MutatorBinding] = []
        self._traversal_order = TraversalOrder.DFS_PREORDER

    def add_mutator(
        self,
        mutator: BFMutator,
        path: Optional[str] = None,
    ) -> "BFMutatable":
        """Attach a mutator to this structure.

        Args:
            mutator: The mutator instance to attach
            path: Optional path to restrict where this mutator applies.

        Returns:
            self for method chaining
        """
        self._mutators.append(MutatorBinding(mutator=mutator, path=path))
        return self

    def remove_mutator(self, mutator: BFMutator) -> "BFMutatable":
        """Remove a mutator from this structure.

        Args:
            mutator: The mutator instance to remove

        Returns:
            self for method chaining
        """
        self._mutators = [b for b in self._mutators if b.mutator is not mutator]
        return self

    def set_traversal_order(self, order: TraversalOrder) -> "BFMutatable":
        """Set the tree traversal order for iteration.

        Args:
            order: The traversal order to use

        Returns:
            self for method chaining
        """
        self._traversal_order = order
        return self

    @property
    def mutators(self) -> list[BFMutator]:
        """Get list of attached mutators."""
        return [b.mutator for b in self._mutators]

    def _get_nodes_in_order(self) -> Generator[tuple[str, BFBasicDataType], None, None]:
        """Yield nodes in the configured traversal order."""
        if self._traversal_order == TraversalOrder.BFS:
            yield from self._bfs_traverse()
        elif self._traversal_order == TraversalOrder.DFS_PREORDER:
            yield from self._dfs_preorder_traverse()
        elif self._traversal_order == TraversalOrder.DFS_POSTORDER:
            yield from self._dfs_postorder_traverse()

    def _traverse_node(
        self, node: BFBasicDataType, path: str
    ) -> Generator[tuple[str, BFBasicDataType], None, None]:
        """Traverse a single node, handling special container types."""
        if isinstance(node, BFLength):
            # BFLength has a _data child that contains the actual children
            if "_data" in node._children:
                data_container = node._children["_data"]
                for name, child in data_container._children.items():
                    child_path = f"{path}.{name}" if path else name
                    yield from self._traverse_node(child, child_path)
        elif isinstance(node, (BFLengthRef, BFCallableRef)):
            # These are leaf nodes with computed values from _field
            # The _field is what we can mutate
            if hasattr(node, "_field"):
                yield (path, node._field)
        elif isinstance(node, BFContainer):
            for name, child in node._children.items():
                child_path = f"{path}.{name}" if path else name
                yield from self._traverse_node(child, child_path)
        else:
            yield (path, node)

    def _bfs_traverse(self) -> Generator[tuple[str, BFBasicDataType], None, None]:
        """Breadth-first traversal."""
        queue: deque[tuple[str, BFBasicDataType]] = deque()

        # Initialize queue based on root type
        if isinstance(self._root, BFLength):
            if "_data" in self._root._children:
                for name, child in self._root._children["_data"]._children.items():
                    queue.append((name, child))
        elif isinstance(self._root, (BFLengthRef, BFCallableRef)):
            if hasattr(self._root, "_field"):
                queue.append(("", self._root._field))
        elif isinstance(self._root, BFContainer):
            for name, child in self._root._children.items():
                queue.append((name, child))
        else:
            queue.append(("", self._root))

        while queue:
            path, node = queue.popleft()

            if isinstance(node, BFLength):
                if "_data" in node._children:
                    for name, child in node._children["_data"]._children.items():
                        child_path = f"{path}.{name}" if path else name
                        queue.append((child_path, child))
            elif isinstance(node, (BFLengthRef, BFCallableRef)):
                if hasattr(node, "_field"):
                    yield (path, node._field)
            elif isinstance(node, BFContainer):
                for name, child in node._children.items():
                    child_path = f"{path}.{name}" if path else name
                    queue.append((child_path, child))
            else:
                yield (path, node)

    def _dfs_preorder_traverse(
        self,
        node: Optional[BFBasicDataType] = None,
        path: str = "",
    ) -> Generator[tuple[str, BFBasicDataType], None, None]:
        """Depth-first preorder traversal."""
        if node is None:
            node = self._root

        yield from self._traverse_node(node, path)

    def _dfs_postorder_traverse(
        self,
        node: Optional[BFBasicDataType] = None,
        path: str = "",
    ) -> Generator[tuple[str, BFBasicDataType], None, None]:
        """Depth-first postorder traversal."""
        if node is None:
            node = self._root

        # For postorder, we still use the same traversal but conceptually
        # children are processed before parents (which matters for containers)
        yield from self._traverse_node(node, path)

    def _get_applicable_mutators(
        self,
        path: str,
        node: BFBasicDataType,
    ) -> Generator[BFMutator, None, None]:
        """Get mutators that apply to a given node."""
        for binding in self._mutators:
            if (
                binding.path is not None
                and binding.path != path
                and not path.endswith(f".{binding.path}")
            ):
                continue

            if binding.mutator.can_mutate(node):
                yield binding.mutator

    def _apply_mutation(
        self,
        path: str,
        node: BFBasicDataType,
        value: Any,
    ) -> bytes:
        """Apply a mutation and return the full packed structure."""
        if hasattr(node, "value"):
            original = node.value
            try:
                node.value = value
                result = self._root.pack()
            finally:
                node.value = original
            return result
        return self._root.pack()

    def __iter__(self) -> Generator[MutationResult, None, None]:
        """Iterate over all mutations.

        Yields:
            MutationResult for each mutation
        """
        yield from self.iterate_mutations()

    def total_count(self) -> int:
        """Get total number of mutations without generating them.

        This is useful for:
        - Progress tracking
        - Determining how to split work across parallel processes
        - Estimating completion time

        Returns:
            Total number of mutations that would be generated
        """
        count = 0
        for path, node in self._get_nodes_in_order():
            if not hasattr(node, "value"):
                continue
            for mutator in self._get_applicable_mutators(path, node):
                for _ in mutator.mutate(node):
                    count += 1
        return count

    def iterate_mutations(
        self,
        order: Optional[TraversalOrder] = None,
        start: int = 0,
        limit: Optional[int] = None,
    ) -> Generator[MutationResult, None, None]:
        """Iterate over mutations with offset and limit support.

        Args:
            order: Optional traversal order override
            start: Starting index (0-based). Skip this many mutations.
            limit: Maximum number of mutations to yield. None = no limit.

        Yields:
            MutationResult for each mutation

        Example:
            # Process mutations 100-149 (50 total)
            for result in mut.iterate_mutations(start=100, limit=50):
                process(result)

            # Resume from where we left off
            for result in mut.iterate_mutations(start=150):
                process(result)
        """
        if order is not None:
            original_order = self._traversal_order
            self._traversal_order = order

        try:
            current_index = 0
            yielded_count = 0

            for path, node in self._get_nodes_in_order():
                if not hasattr(node, "value"):
                    continue

                original_value = node.value

                for mutator in self._get_applicable_mutators(path, node):
                    for mutated_value, description in mutator.mutate(node):
                        # Check if we should skip this mutation
                        if current_index < start:
                            current_index += 1
                            continue

                        # Check if we've hit the limit
                        if limit is not None and yielded_count >= limit:
                            return

                        packed_data = self._apply_mutation(path, node, mutated_value)

                        yield MutationResult(
                            index=current_index,
                            path=path,
                            original_value=original_value,
                            mutated_value=mutated_value,
                            mutator_name=mutator.name,
                            metadata=mutator.metadata,
                            description=description,
                            packed_data=packed_data,
                        )

                        current_index += 1
                        yielded_count += 1
        finally:
            if order is not None:
                self._traversal_order = original_order

    def get_mutation_summary(self) -> dict[str, Any]:
        """Get a summary of the mutation configuration.

        Returns:
            Dictionary with mutation statistics
        """
        paths: dict[str, list[str]] = {}

        for path, node in self._get_nodes_in_order():
            if not hasattr(node, "value"):
                continue

            applicable = [m.name for m in self._get_applicable_mutators(path, node)]
            if applicable:
                paths[path] = applicable

        return {
            "total_mutators": len(self._mutators),
            "traversal_order": self._traversal_order.name,
            "mutation_points": paths,
            "total_mutations": self.total_count(),
        }


# =============================================================================
# Convenience Functions
# =============================================================================


def create_integer_mutator_suite() -> list[BFMutator]:
    """Create a comprehensive suite of integer mutators.

    Returns:
        List of all integer-related mutators
    """
    return [
        BFIntegerBoundaryMutator(),
        BFIntegerSignMutator(),
        BFIntegerSpecialValueMutator(),
        BFIntegerBitPatternMutator(),
    ]


def create_buffer_mutator_suite() -> list[BFMutator]:
    """Create a comprehensive suite of buffer mutators.

    Returns:
        List of all buffer-related mutators
    """
    return [
        BFBufferLengthMutator(),
        BFBufferContentMutator(),
        BFBufferNullTerminationMutator(),
    ]


def create_full_mutator_suite() -> list[BFMutator]:
    """Create a complete suite of all mutators.

    Returns:
        List of all available mutators
    """
    return create_integer_mutator_suite() + create_buffer_mutator_suite()


def mutate(
    bf_type: BFBasicDataType,
    mutators: Optional[list[BFMutator]] = None,
    order: TraversalOrder = TraversalOrder.DFS_PREORDER,
    start: int = 0,
    limit: Optional[int] = None,
) -> Generator[MutationResult, None, None]:
    """Convenience function to iterate mutations on a BitFactory type.

    Args:
        bf_type: The BitFactory type to mutate
        mutators: List of mutators to apply (defaults to full suite)
        order: Traversal order for nested structures
        start: Starting index for resumption
        limit: Maximum mutations to yield

    Yields:
        MutationResult for each mutation
    """
    wrapper = BFMutatable(bf_type)
    wrapper.set_traversal_order(order)

    for mutator in mutators or create_full_mutator_suite():
        wrapper.add_mutator(mutator)

    yield from wrapper.iterate_mutations(start=start, limit=limit)
