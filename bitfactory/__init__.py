"""BitFactory package public API."""

from .bitfactory import (
    BFBasicDataType,
    BFBuffer,
    BFCallableRef,
    BFContainer,
    BFEndian,
    BFIntegerField,
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
from .registry import (
    get_mutator,
    get_type,
    list_mutators,
    list_types,
    load_plugins,
    mutators_with_tag,
    register_mutator,
    register_type,
    types_with_tag,
)

# Discover and register any types/mutators contributed by installed plugin
# packages via entry points (see bitfactory.registry). Safe to call at import:
# individual plugin failures are logged and skipped.
load_plugins()

__all__ = [
    # Core types
    "BFBasicDataType",
    "BFBuffer",
    "BFContainer",
    "BFEndian",
    "BFIntegerField",
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
    # Registry / extensibility
    "register_type",
    "register_mutator",
    "get_type",
    "get_mutator",
    "list_types",
    "list_mutators",
    "types_with_tag",
    "mutators_with_tag",
    "load_plugins",
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
