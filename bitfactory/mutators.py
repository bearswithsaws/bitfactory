"""BitFactory Mutators Module

This module provides a mutation system for BitFactory types that enables
systematic generation of edge-case and potentially invalid values based
on Common Weakness Enumeration (CWE) standards.

Mutators can be attached to any BF type at any level in a hierarchy,
and the system supports recursive iteration with configurable traversal
orders (BFS, DFS preorder, DFS postorder).
"""

import abc
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Generator, Optional, Union

from .bitfactory import (
    BFBasicDataType,
    BFBuffer,
    BFContainer,
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
        path: Dot-separated path to the mutated field (e.g., "header.length")
        original_value: The original value before mutation
        mutated_value: The mutated value
        mutator_name: Name of the mutator that produced this value
        cwe_ids: List of CWE identifiers relevant to this mutation
        description: Human-readable description of the mutation
        packed_data: The full packed binary data with the mutation applied
    """

    path: str
    original_value: Any
    mutated_value: Any
    mutator_name: str
    cwe_ids: list[str]
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
    boundary conditions, and potentially invalid states based on CWE
    (Common Weakness Enumeration) standards.

    Subclasses must implement the `mutate` method and specify which
    BF types they can mutate via `supported_types`.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable name for this mutator."""

    @property
    @abc.abstractmethod
    def cwe_ids(self) -> list[str]:
        """List of CWE identifiers this mutator addresses."""

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
    def mutate(
        self, bf_type: BFBasicDataType
    ) -> Generator[tuple[Any, str], None, None]:
        """Generate mutated values for the given type.

        Args:
            bf_type: A BitFactory type instance to mutate

        Yields:
            Tuple of (mutated_value, description) for each mutation
        """


# =============================================================================
# Integer Mutators - CWE-based edge cases
# =============================================================================


class BFIntegerBoundaryMutator(BFMutator):
    """Generates integer boundary values to test overflow/underflow conditions.

    This mutator produces values at and around the boundaries of integer
    types, targeting vulnerabilities like:
    - CWE-190: Integer Overflow or Wraparound
    - CWE-191: Integer Underflow or Wraparound
    - CWE-128: Wrap-around Error
    """

    @property
    def name(self) -> str:
        return "Integer Boundary Mutator"

    @property
    def cwe_ids(self) -> list[str]:
        return ["CWE-190", "CWE-191", "CWE-128"]

    @property
    def supported_types(self) -> tuple[type, ...]:
        return (BFUInt8, BFSInt8, BFUInt16, BFSInt16, BFUInt32, BFSInt32)

    def _get_boundaries(
        self, bf_type: BFBasicDataType
    ) -> Generator[tuple[int, str], None, None]:
        """Generate boundary values based on type."""
        # Determine if signed and bit width
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
            max_val = (1 << (bits - 1)) - 1  # e.g., 127 for 8-bit
            min_val = -(1 << (bits - 1))  # e.g., -128 for 8-bit
            unsigned_max = (1 << bits) - 1

            yield (max_val, f"MAX_SIGNED_{bits} ({max_val})")
            yield (max_val + 1, f"MAX_SIGNED_{bits}+1 overflow ({max_val + 1})")
            yield (min_val, f"MIN_SIGNED_{bits} ({min_val})")
            yield (min_val - 1, f"MIN_SIGNED_{bits}-1 underflow ({min_val - 1})")
            yield (0, "Zero")
            yield (-1, "Negative one")
            yield (1, "One")
            # Values that wrap when interpreted as unsigned
            yield (unsigned_max, f"MAX_UNSIGNED_{bits} as signed ({unsigned_max})")
        else:
            max_val = (1 << bits) - 1  # e.g., 255 for 8-bit
            min_val = 0

            yield (max_val, f"MAX_UNSIGNED_{bits} ({max_val})")
            yield (max_val + 1, f"MAX_UNSIGNED_{bits}+1 overflow ({max_val + 1})")
            yield (min_val, f"MIN_UNSIGNED_{bits} (0)")
            yield (min_val - 1, f"MIN_UNSIGNED_{bits}-1 underflow (-1)")
            yield (1, "One")
            # Half-max for midpoint testing
            yield (max_val // 2, f"HALF_MAX_{bits} ({max_val // 2})")
            yield ((max_val // 2) + 1, f"HALF_MAX_{bits}+1 ({(max_val // 2) + 1})")

    def mutate(
        self, bf_type: BFBasicDataType
    ) -> Generator[tuple[Any, str], None, None]:
        if not self.can_mutate(bf_type):
            return

        for value, description in self._get_boundaries(bf_type):
            yield (value, description)


class BFIntegerSignMutator(BFMutator):
    """Tests sign-related integer vulnerabilities.

    Targets:
    - CWE-194: Unexpected Sign Extension
    - CWE-195: Signed to Unsigned Conversion Error
    - CWE-196: Unsigned to Signed Conversion Error
    """

    @property
    def name(self) -> str:
        return "Integer Sign Mutator"

    @property
    def cwe_ids(self) -> list[str]:
        return ["CWE-194", "CWE-195", "CWE-196"]

    @property
    def supported_types(self) -> tuple[type, ...]:
        return (BFUInt8, BFSInt8, BFUInt16, BFSInt16, BFUInt32, BFSInt32)

    def mutate(
        self, bf_type: BFBasicDataType
    ) -> Generator[tuple[Any, str], None, None]:
        if not self.can_mutate(bf_type):
            return

        is_signed = isinstance(bf_type, (BFSInt8, BFSInt16, BFSInt32))

        if isinstance(bf_type, (BFUInt8, BFSInt8)):
            bits = 8
        elif isinstance(bf_type, (BFUInt16, BFSInt16)):
            bits = 16
        else:
            bits = 32

        # Sign extension trigger values (high bit set)
        sign_bit_set = 1 << (bits - 1)
        yield (sign_bit_set, f"Sign bit set (0x{sign_bit_set:X})")

        # All bits set except sign bit
        all_except_sign = (1 << (bits - 1)) - 1
        yield (all_except_sign, f"All bits except sign (0x{all_except_sign:X})")

        # Patterns that cause issues when cast between signed/unsigned
        if is_signed:
            yield (-1, "Negative one (0xFF... when cast to unsigned)")
            yield (
                -(1 << (bits - 2)),
                f"Large negative (-{1 << (bits - 2)})",
            )
        else:
            # Values > signed max that become negative when cast
            signed_max = (1 << (bits - 1)) - 1
            yield (
                signed_max + 1,
                f"Signed overflow when cast (0x{signed_max + 1:X})",
            )
            yield (
                (1 << bits) - 1,
                f"All bits set - becomes -1 signed (0x{(1 << bits) - 1:X})",
            )

        # Byte patterns that sign-extend differently
        if bits > 8:
            yield (0x80, "0x80 - sign extends in smaller type")
            yield (0x7F, "0x7F - max positive in smaller type")
            if bits > 16:
                yield (0x8000, "0x8000 - sign extends from 16-bit")
                yield (0x7FFF, "0x7FFF - max positive 16-bit")


class BFIntegerSpecialValueMutator(BFMutator):
    """Generates special integer values that often cause issues.

    Targets:
    - CWE-369: Divide By Zero
    - CWE-682: Incorrect Calculation
    - CWE-681: Incorrect Conversion between Numeric Types
    """

    @property
    def name(self) -> str:
        return "Integer Special Value Mutator"

    @property
    def cwe_ids(self) -> list[str]:
        return ["CWE-369", "CWE-682", "CWE-681"]

    @property
    def supported_types(self) -> tuple[type, ...]:
        return (BFUInt8, BFSInt8, BFUInt16, BFSInt16, BFUInt32, BFSInt32)

    def mutate(
        self, bf_type: BFBasicDataType
    ) -> Generator[tuple[Any, str], None, None]:
        if not self.can_mutate(bf_type):
            return

        # Zero - divide by zero, null pointer arithmetic
        yield (0, "Zero (potential divide-by-zero)")

        # One - off-by-one errors
        yield (1, "One (off-by-one boundary)")

        # Powers of two - common allocation sizes, alignment issues
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

        # Common size values that cause issues
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
            if val <= max_val + 1:  # Allow one over for overflow testing
                yield (val, desc)


class BFIntegerBitPatternMutator(BFMutator):
    """Generates interesting bit patterns for testing.

    Targets:
    - CWE-704: Incorrect Type Conversion or Cast
    - CWE-188: Reliance on Data/Memory Layout
    """

    @property
    def name(self) -> str:
        return "Integer Bit Pattern Mutator"

    @property
    def cwe_ids(self) -> list[str]:
        return ["CWE-704", "CWE-188"]

    @property
    def supported_types(self) -> tuple[type, ...]:
        return (BFUInt8, BFSInt8, BFUInt16, BFSInt16, BFUInt32, BFSInt32)

    def mutate(
        self, bf_type: BFBasicDataType
    ) -> Generator[tuple[Any, str], None, None]:
        if not self.can_mutate(bf_type):
            return

        if isinstance(bf_type, (BFUInt8, BFSInt8)):
            bits = 8
        elif isinstance(bf_type, (BFUInt16, BFSInt16)):
            bits = 16
        else:
            bits = 32

        # All bits set
        all_ones = (1 << bits) - 1
        yield (all_ones, f"All bits set (0x{all_ones:X})")

        # Alternating bit patterns
        if bits == 8:
            yield (0xAA, "Alternating bits 10101010")
            yield (0x55, "Alternating bits 01010101")
        elif bits == 16:
            yield (0xAAAA, "Alternating bits 1010...")
            yield (0x5555, "Alternating bits 0101...")
        else:
            yield (0xAAAAAAAA, "Alternating bits 1010...")
            yield (0x55555555, "Alternating bits 0101...")

        # Single bit walking
        for i in range(min(bits, 8)):  # First 8 bits
            val = 1 << i
            yield (val, f"Single bit {i} set (0x{val:X})")

        # High bits for larger types
        if bits > 8:
            for i in [bits - 1, bits - 2, bits // 2]:
                val = 1 << i
                yield (val, f"Bit {i} set (0x{val:X})")

        # Nibble patterns
        if bits >= 8:
            yield (0x0F, "Low nibble set")
            yield (0xF0, "High nibble of byte set")
        if bits >= 16:
            yield (0x00FF, "Low byte set")
            yield (0xFF00, "High byte of word set")
        if bits >= 32:
            yield (0x0000FFFF, "Low word set")
            yield (0xFFFF0000, "High word set")


# =============================================================================
# Buffer Mutators - CWE-based edge cases
# =============================================================================


class BFBufferLengthMutator(BFMutator):
    """Generates buffer length edge cases.

    Targets:
    - CWE-120: Buffer Copy without Checking Size
    - CWE-787: Out-of-bounds Write
    - CWE-125: Out-of-bounds Read
    - CWE-131: Incorrect Calculation of Buffer Size
    """

    @property
    def name(self) -> str:
        return "Buffer Length Mutator"

    @property
    def cwe_ids(self) -> list[str]:
        return ["CWE-120", "CWE-787", "CWE-125", "CWE-131"]

    @property
    def supported_types(self) -> tuple[type, ...]:
        return (BFBuffer,)

    def __init__(self, length_variations: Optional[list[int]] = None):
        """Initialize with optional custom length variations.

        Args:
            length_variations: List of length adjustments to apply
                             (e.g., [-1, 0, 1, 255, 256] for various off-by-N)
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

    def mutate(
        self, bf_type: BFBasicDataType
    ) -> Generator[tuple[Any, str], None, None]:
        if not self.can_mutate(bf_type):
            return

        original_len = len(bf_type.value)

        # Empty buffer
        yield (b"", "Empty buffer (length=0)")

        # Single byte
        yield (b"\x00", "Single null byte")
        yield (b"\xff", "Single 0xFF byte")

        # Length variations relative to original
        for delta in self._length_variations:
            new_len = original_len + delta
            if new_len > 0 and new_len != original_len:
                # Pad with pattern or truncate
                if new_len > original_len:
                    new_data = bf_type.value + (b"\x41" * (new_len - original_len))
                else:
                    new_data = bf_type.value[:new_len]
                yield (new_data, f"Length {original_len} -> {new_len} (delta={delta:+d})")

        # Common boundary sizes
        boundary_sizes = [1, 2, 4, 8, 16, 32, 64, 128, 255, 256, 512, 1024, 4096]
        for size in boundary_sizes:
            if size != original_len:
                data = (b"\x42" * size)
                yield (data, f"Boundary size {size} bytes")


class BFBufferContentMutator(BFMutator):
    """Generates buffers with special content patterns.

    Targets:
    - CWE-134: Use of Externally-Controlled Format String
    - CWE-78: OS Command Injection
    - CWE-89: SQL Injection
    - CWE-79: XSS (if buffer is used in web context)
    """

    @property
    def name(self) -> str:
        return "Buffer Content Mutator"

    @property
    def cwe_ids(self) -> list[str]:
        return ["CWE-134", "CWE-78", "CWE-89", "CWE-79"]

    @property
    def supported_types(self) -> tuple[type, ...]:
        return (BFBuffer,)

    def mutate(
        self, bf_type: BFBasicDataType
    ) -> Generator[tuple[Any, str], None, None]:
        if not self.can_mutate(bf_type):
            return

        original_len = max(len(bf_type.value), 16)

        # Null bytes
        yield (b"\x00" * original_len, "All null bytes")
        yield (bf_type.value[:1] + b"\x00" + bf_type.value[2:] if len(bf_type.value) > 2 else b"\x00",
               "Embedded null byte")

        # High bytes
        yield (b"\xff" * original_len, "All 0xFF bytes")
        yield (b"\x80" * original_len, "All 0x80 bytes (high bit set)")

        # Format string patterns (for testing format string vulnerabilities)
        format_patterns = [
            b"%s%s%s%s%s",
            b"%n%n%n%n%n",
            b"%x%x%x%x%x",
            b"AAAA%08x.%08x.%08x.%08x",
            b"%p%p%p%p%p",
        ]
        for pattern in format_patterns:
            yield (pattern, f"Format string: {pattern[:20]}")

        # Long repetitive patterns
        yield (b"A" * 1024, "Long A pattern (1024 bytes)")
        yield (b"A" * 4096, "Long A pattern (4096 bytes)")

        # Pattern with incrementing bytes
        yield (bytes(range(256)), "All byte values 0x00-0xFF")

        # Patterns that might break string handling
        yield (b"\r\n" * 100, "CRLF repetition")
        yield (b"/../" * 50, "Path traversal pattern")


class BFBufferNullTerminationMutator(BFMutator):
    """Tests null termination handling in buffers.

    Targets:
    - CWE-170: Improper Null Termination
    - CWE-126: Buffer Over-read
    """

    @property
    def name(self) -> str:
        return "Buffer Null Termination Mutator"

    @property
    def cwe_ids(self) -> list[str]:
        return ["CWE-170", "CWE-126"]

    @property
    def supported_types(self) -> tuple[type, ...]:
        return (BFBuffer,)

    def mutate(
        self, bf_type: BFBasicDataType
    ) -> Generator[tuple[Any, str], None, None]:
        if not self.can_mutate(bf_type):
            return

        original = bf_type.value
        length = len(original)

        # No null terminator
        if original.endswith(b"\x00"):
            yield (original[:-1], "Removed null terminator")
        else:
            yield (original + b"A" * 10, "Extended without null terminator")

        # Multiple null terminators
        yield (original + b"\x00\x00\x00", "Multiple null terminators")

        # Null in middle
        if length > 2:
            mid = length // 2
            yield (original[:mid] + b"\x00" + original[mid + 1:], "Null in middle")

        # Null at start
        yield (b"\x00" + original[1:] if length > 0 else b"\x00", "Null at start")

        # String after null
        yield (b"AAAA\x00BBBB", "Data after null terminator")


# =============================================================================
# Mutatable Wrapper - Makes any BF type iterable with mutations
# =============================================================================


class BFMutatable:
    """Wrapper that adds mutation capabilities to any BitFactory structure.

    This class wraps a BFBasicDataType (including BFContainer hierarchies)
    and provides iteration over all possible mutations based on attached
    mutators.

    Example:
        >>> container = BFContainer()
        >>> container.header = BFUInt32(value=100)
        >>> container.data = BFBuffer(b"test")
        >>>
        >>> mut = BFMutatable(container)
        >>> mut.add_mutator(BFIntegerBoundaryMutator())
        >>> mut.add_mutator(BFBufferLengthMutator())
        >>>
        >>> for result in mut:
        ...     print(f"{result.path}: {result.description}")
        ...     # result.packed_data contains the full mutated binary
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
                  If None, applies to all matching types in the hierarchy.

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

    def _collect_nodes(
        self,
        node: BFBasicDataType,
        path: str = "",
    ) -> list[tuple[str, BFBasicDataType]]:
        """Collect all nodes in the tree with their paths.

        Args:
            node: Current node
            path: Current path string

        Returns:
            List of (path, node) tuples
        """
        nodes = []

        if isinstance(node, BFContainer):
            for name, child in node._children.items():
                child_path = f"{path}.{name}" if path else name
                nodes.extend(self._collect_nodes(child, child_path))
            # Also include the container itself if it's not the root
            if path:
                nodes.append((path, node))
        else:
            nodes.append((path, node))

        return nodes

    def _get_nodes_in_order(self) -> Generator[tuple[str, BFBasicDataType], None, None]:
        """Yield nodes in the configured traversal order."""
        if self._traversal_order == TraversalOrder.BFS:
            yield from self._bfs_traverse()
        elif self._traversal_order == TraversalOrder.DFS_PREORDER:
            yield from self._dfs_preorder_traverse()
        elif self._traversal_order == TraversalOrder.DFS_POSTORDER:
            yield from self._dfs_postorder_traverse()

    def _bfs_traverse(self) -> Generator[tuple[str, BFBasicDataType], None, None]:
        """Breadth-first traversal."""
        queue: deque[tuple[str, BFBasicDataType]] = deque()

        if isinstance(self._root, BFContainer):
            for name, child in self._root._children.items():
                queue.append((name, child))
        else:
            queue.append(("", self._root))

        while queue:
            path, node = queue.popleft()

            # Yield non-container nodes, or container nodes with mutatable fields
            if not isinstance(node, BFContainer):
                yield (path, node)
            else:
                # Add children to queue
                for name, child in node._children.items():
                    child_path = f"{path}.{name}" if path else name
                    queue.append((child_path, child))

    def _dfs_preorder_traverse(
        self,
        node: Optional[BFBasicDataType] = None,
        path: str = "",
    ) -> Generator[tuple[str, BFBasicDataType], None, None]:
        """Depth-first preorder traversal (process node before children)."""
        if node is None:
            node = self._root

        if isinstance(node, BFContainer):
            for name, child in node._children.items():
                child_path = f"{path}.{name}" if path else name
                yield from self._dfs_preorder_traverse(child, child_path)
        else:
            yield (path, node)

    def _dfs_postorder_traverse(
        self,
        node: Optional[BFBasicDataType] = None,
        path: str = "",
    ) -> Generator[tuple[str, BFBasicDataType], None, None]:
        """Depth-first postorder traversal (process children before node)."""
        if node is None:
            node = self._root

        if isinstance(node, BFContainer):
            for name, child in node._children.items():
                child_path = f"{path}.{name}" if path else name
                yield from self._dfs_postorder_traverse(child, child_path)
        else:
            yield (path, node)

    def _get_applicable_mutators(
        self,
        path: str,
        node: BFBasicDataType,
    ) -> Generator[BFMutator, None, None]:
        """Get mutators that apply to a given node.

        Args:
            path: The node's path in the tree
            node: The node instance

        Yields:
            Applicable mutator instances
        """
        for binding in self._mutators:
            # Check path restriction
            if binding.path is not None:
                if binding.path != path and not path.endswith(f".{binding.path}"):
                    continue

            # Check type compatibility
            if binding.mutator.can_mutate(node):
                yield binding.mutator

    def _apply_mutation(
        self,
        path: str,
        node: BFBasicDataType,
        value: Any,
    ) -> bytes:
        """Apply a mutation and return the full packed structure.

        Args:
            path: Path to the node being mutated
            node: The node to mutate
            value: The mutated value to apply

        Returns:
            Packed bytes of the entire structure with mutation applied
        """
        # Store original value
        if hasattr(node, "value"):
            original = node.value
            # Apply mutation
            try:
                node.value = value
                result = self._root.pack()
            finally:
                # Restore original
                node.value = original
            return result
        return self._root.pack()

    def __iter__(self) -> Generator[MutationResult, None, None]:
        """Iterate over all mutations.

        Yields:
            MutationResult for each mutation
        """
        yield from self.iterate_mutations()

    def iterate_mutations(
        self,
        order: Optional[TraversalOrder] = None,
    ) -> Generator[MutationResult, None, None]:
        """Iterate over all mutations with optional order override.

        Args:
            order: Optional traversal order override

        Yields:
            MutationResult for each mutation
        """
        if order is not None:
            original_order = self._traversal_order
            self._traversal_order = order

        try:
            for path, node in self._get_nodes_in_order():
                if not hasattr(node, "value"):
                    continue

                original_value = node.value

                for mutator in self._get_applicable_mutators(path, node):
                    for mutated_value, description in mutator.mutate(node):
                        packed_data = self._apply_mutation(path, node, mutated_value)

                        yield MutationResult(
                            path=path,
                            original_value=original_value,
                            mutated_value=mutated_value,
                            mutator_name=mutator.name,
                            cwe_ids=mutator.cwe_ids,
                            description=description,
                            packed_data=packed_data,
                        )
        finally:
            if order is not None:
                self._traversal_order = original_order

    def count_mutations(self) -> int:
        """Count total number of mutations without generating them.

        Returns:
            Total number of mutations that would be generated
        """
        count = 0
        for path, node in self._get_nodes_in_order():
            if not hasattr(node, "value"):
                continue
            for mutator in self._get_applicable_mutators(path, node):
                if mutator.can_mutate(node):
                    # We need to actually count mutations
                    for _ in mutator.mutate(node):
                        count += 1
        return count

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
            "estimated_mutations": self.count_mutations(),
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
) -> Generator[MutationResult, None, None]:
    """Convenience function to iterate mutations on a BitFactory type.

    Args:
        bf_type: The BitFactory type to mutate
        mutators: List of mutators to apply (defaults to full suite)
        order: Traversal order for nested structures

    Yields:
        MutationResult for each mutation
    """
    wrapper = BFMutatable(bf_type)
    wrapper.set_traversal_order(order)

    for mutator in (mutators or create_full_mutator_suite()):
        wrapper.add_mutator(mutator)

    yield from wrapper
