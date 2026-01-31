"""BitFactory Module imports"""

from .bitfactory import (
    BFBasicDataType,
    BFBuffer,
    BFCallableRef,
    BFContainer,
    BFEndian,
    BFLength,
    BFLengthRef,
    BFRefBase,
    BFSInt8,
    BFSInt16,
    BFSInt32,
    BFUInt8,
    BFUInt16,
    BFUInt32,
)
from .mutators import (
    BFBitFlipMutator,
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
    MutatorBinding,
    TraversalOrder,
    create_buffer_mutator_suite,
    create_full_mutator_suite,
    create_integer_mutator_suite,
    mutate,
)

__all__ = [
    # Core types
    "BFBasicDataType",
    "BFBuffer",
    "BFContainer",
    "BFEndian",
    "BFLength",
    "BFLengthRef",
    "BFCallableRef",
    "BFRefBase",
    "BFSInt8",
    "BFSInt16",
    "BFSInt32",
    "BFUInt8",
    "BFUInt16",
    "BFUInt32",
    # Mutator system
    "BFMutator",
    "BFMutatable",
    "MutationResult",
    "MutatorBinding",
    "TraversalOrder",
    # Integer mutators
    "BFIntegerBoundaryMutator",
    "BFIntegerSignMutator",
    "BFIntegerSpecialValueMutator",
    "BFIntegerBitPatternMutator",
    # Bit manipulation mutators
    "BFBitFlipMutator",
    # Buffer mutators
    "BFBufferLengthMutator",
    "BFBufferContentMutator",
    "BFBufferNullTerminationMutator",
    # Convenience functions
    "create_integer_mutator_suite",
    "create_buffer_mutator_suite",
    "create_full_mutator_suite",
    "mutate",
]
