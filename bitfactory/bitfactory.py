"""BitFactory core types and containers.

Field types carry their own metadata (bit width, signedness, tags) so that
downstream tooling (mutators, discovery, pretty-printing) can be written once and
work with any type, including third-party types registered via
:mod:`bitfactory.registry`.
"""

import abc
import binascii
import logging
from collections import OrderedDict
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Literal

from .exceptions import BFEndianException, BFRangeException, BFTypeException
from .registry import register_type

ByteOrder = Literal["little", "big"]


class BFEndian(Enum):
    """Byte order for multi-byte fields."""

    LITTLE = 1
    BIG = 2


_ENDIAN_TO_STR: "dict[BFEndian, ByteOrder]" = {
    BFEndian.LITTLE: "little",
    BFEndian.BIG: "big",
}


def _endian_str(endian: BFEndian) -> ByteOrder:
    """Normalize a :class:`BFEndian` to ``int.to_bytes`` order string."""
    try:
        return _ENDIAN_TO_STR[endian]
    except KeyError as exc:
        raise BFEndianException(f"Unknown endianness: {endian!r}") from exc


class BFBasicDataType(abc.ABC):
    """Abstract base class for all field types.

    Subclasses must implement :meth:`pack`. Every type exposes a ``tags`` set
    used for trait-based dispatch (e.g. matching mutators to fields). By default
    tags come from the class-level ``TAGS`` attribute; types whose tags depend on
    instance/class metadata (integers) override the ``tags`` property.
    """

    TAGS: frozenset = frozenset()

    #: Set on the storage field of a mutable computed field so the mutation
    #: engine can pause its owner's recomputation; None for ordinary fields.
    _computed_owner: "BFComputed | None" = None

    @property
    def tags(self) -> frozenset:
        """Trait tags describing this field (used for mutator dispatch)."""
        return type(self).TAGS

    # Every node can be placed in a container and can walk to the tree root.
    # These live on the base (not just containers) so that leaf fields — in
    # particular computed fields that reference other nodes — are first-class
    # tree citizens. They default lazily to avoid requiring every __init__ to
    # initialize them.

    @property
    def name(self):
        """The field's name within its parent container (or None)."""
        return getattr(self, "_name", None)

    @name.setter
    def name(self, name):
        self._name = name

    @property
    def parent(self):
        """The container this field was added to (or None for the root)."""
        return getattr(self, "_parent", None)

    @parent.setter
    def parent(self, parent):
        self._parent = parent

    def root(self) -> "BFBasicDataType":
        """Walk parent pointers to the top of the tree."""
        node = self
        while node.parent is not None:
            node = node.parent
        return node

    @abc.abstractmethod
    def pack(self) -> bytes:
        """Return the packed binary representation of this field."""

    @abc.abstractmethod
    def pretty_print(self, indent: int = 0) -> str:
        """Return a human-readable, indented rendering of this field."""

    if TYPE_CHECKING:
        # These describe the optional field interface used by generic tooling
        # (mutators, discovery). They are declared for the type checker only;
        # concrete field types provide the real implementations at runtime.
        # Declaring them here (rather than as real base properties) keeps them
        # out of the runtime attribute namespace, so containers do not treat
        # "value"/"bit_width"/"signed" as reserved child-field names.

        @property
        def value(self) -> Any: ...

        @value.setter
        def value(self, val: Any) -> None: ...

        @property
        def bit_width(self) -> int: ...

        @property
        def signed(self) -> bool: ...

        @property
        def length(self) -> int: ...


class BFIntegerField(BFBasicDataType):
    """Base class for fixed-width integer fields.

    A concrete integer type is declared with just two class attributes::

        @register_type("uint24")
        class BFUInt24(BFIntegerField):
            BYTE_WIDTH = 3
            SIGNED = False

    Width is arbitrary (24-bit and 64-bit types work with no special casing).
    Values are stored masked to the unsigned width; two's-complement is handled
    naturally at pack time, so signed and unsigned share one code path.
    """

    #: Width of the field in bytes. Subclasses must set this.
    BYTE_WIDTH: int = 0
    #: Whether the field is signed (affects display and mutator boundaries).
    SIGNED: bool = False

    #: Human-readable width nouns for pretty-printing.
    _WIDTH_NOUNS = {1: "Byte", 2: "Short", 4: "Long", 8: "Quad"}

    def __init__(self, value=0, endian: BFEndian = BFEndian.LITTLE):
        if self.BYTE_WIDTH <= 0:
            raise BFTypeException(
                f"{type(self).__name__} must define a positive BYTE_WIDTH"
            )
        self._endian = _endian_str(endian)
        self._mask = (1 << self.bit_width) - 1
        self.value = value

    @property
    def bit_width(self) -> int:
        """Width of the field in bits."""
        return self.BYTE_WIDTH * 8

    @property
    def signed(self) -> bool:
        """Whether the field is signed."""
        return self.SIGNED

    @property
    def tags(self) -> frozenset:
        return frozenset(
            {
                "integer",
                "scalar",
                "signed" if self.SIGNED else "unsigned",
                f"width:{self.bit_width}",
            }
        )

    @property
    def value(self) -> int:
        return self._value

    @value.setter
    def value(self, val) -> None:
        if isinstance(val, bool):
            # bool is an int subclass; reject to avoid surprising coercion.
            raise BFTypeException(f"{type(self).__name__} value must be int or bytes")
        if isinstance(val, int):
            self._value = val & self._mask
        elif isinstance(val, (bytes, bytearray)):
            if len(val) > self.BYTE_WIDTH:
                raise BFRangeException(
                    f"{type(self).__name__} accepts at most {self.BYTE_WIDTH} bytes, "
                    f"got {len(val)}"
                )
            self._value = int.from_bytes(bytes(val), self._endian) & self._mask
        else:
            raise BFTypeException(f"{type(self).__name__} value must be int or bytes")

    @property
    def length(self) -> int:
        return self.BYTE_WIDTH

    def pack(self) -> bytes:
        return self._value.to_bytes(self.BYTE_WIDTH, self._endian)

    def __str__(self) -> str:
        return self.pretty_print()

    def pretty_print(self, indent: int = 0) -> str:
        noun = self._WIDTH_NOUNS.get(self.BYTE_WIDTH, f"{self.BYTE_WIDTH}-byte")
        sign = "Signed" if self.SIGNED else "Unsigned"
        digits = self.BYTE_WIDTH * 2
        return " " * indent + "|- " + f"{sign} {noun} 0x{self.value:0{digits}X}"


@register_type("uint8")
class BFUInt8(BFIntegerField):
    """Unsigned 8-bit integer."""

    BYTE_WIDTH = 1
    SIGNED = False


@register_type("sint8")
class BFSInt8(BFIntegerField):
    """Signed 8-bit integer."""

    BYTE_WIDTH = 1
    SIGNED = True


@register_type("uint16")
class BFUInt16(BFIntegerField):
    """Unsigned 16-bit integer."""

    BYTE_WIDTH = 2
    SIGNED = False


@register_type("sint16")
class BFSInt16(BFIntegerField):
    """Signed 16-bit integer."""

    BYTE_WIDTH = 2
    SIGNED = True


@register_type("uint32")
class BFUInt32(BFIntegerField):
    """Unsigned 32-bit integer."""

    BYTE_WIDTH = 4
    SIGNED = False


@register_type("sint32")
class BFSInt32(BFIntegerField):
    """Signed 32-bit integer."""

    BYTE_WIDTH = 4
    SIGNED = True


@register_type("buffer")
class BFBuffer(BFBasicDataType):
    """Variable-length byte buffer."""

    TAGS = frozenset({"buffer", "bytes"})

    def __init__(self, value=b""):
        self.value = value

    @property
    def length(self) -> int:
        return len(self._value)

    def pack(self) -> bytes:
        return self._value

    @property
    def value(self) -> bytes:
        return self._value

    @value.setter
    def value(self, val) -> None:
        if isinstance(val, (bytes, bytearray)):
            self._value = bytes(val)
        else:
            raise BFTypeException("BFBuffer value must be bytes")

    def __str__(self) -> str:
        return self.pretty_print()

    def pretty_print(self, indent: int = 0) -> str:
        short_val = str(binascii.hexlify(self.pack()))
        if self.length > 10:
            short_val = str(binascii.hexlify(self.pack()[:10])) + "..."
        return " " * indent + "|- " + f"Buffer {short_val}"


@register_type("container")
class BFContainer(BFBasicDataType):
    """Ordered collection of named child fields.

    Children may be assigned with attribute syntax
    (``container.field = BFUInt8()``) or via :meth:`add` with dotted paths.
    Attribute names that collide with an existing attribute or method of the
    container class (``pack``, ``name``, ``parent``, ``add``, ``tags``, and
    ``value`` on containers that define it) are rejected, so children can never
    shadow methods. Common protocol field names such as ``length`` remain
    usable.
    """

    TAGS = frozenset({"container"})

    def __init__(self):
        self._children = OrderedDict()
        self._name = None
        self._parent = None

    def add(self, name, obj):
        root = name
        obj._parent = self
        sub_container = None
        logging.debug(name)
        if "." in root:
            root, sub_container = root.split(".", 1)
        logging.debug("%s : %s", root, sub_container)
        logging.debug("Adding %s to %s (sub: %s)", type(obj), root, sub_container)
        if root is not None and sub_container is None and isinstance(obj, BFContainer):
            obj.name = root
        if root in iter(self._children) and sub_container is not None:
            # Recurse into the existing sub-container.
            self._children[root].add(sub_container, obj)
        else:
            self._children[root] = obj

        return self

    def __getattr__(self, name):
        # __getattr__ is only consulted when normal attribute lookup fails, so
        # real methods/attributes always win over children of the same name.
        children = self.__dict__.get("_children")
        if children is not None and name in children:
            return children[name]
        raise AttributeError(name)

    def __setattr__(self, name, obj):
        if isinstance(obj, BFBasicDataType) and not name.startswith("_"):
            if hasattr(type(self), name):
                raise BFTypeException(
                    f"{name!r} is reserved and cannot be used as a field name"
                )
            self.add(name, obj)
        else:
            super().__setattr__(name, obj)

    @property
    def children(self) -> "list[BFBasicDataType]":
        """The container's direct children, in insertion order."""
        return list(self._children.values())

    def pack(self) -> bytes:
        return b"".join(child.pack() for child in self._children.values())

    def __str__(self) -> str:
        return self.pretty_print()

    def pretty_print(self, indent: int = 0) -> str:
        ret = " " * indent + f"+{self.name}\n"
        for child in self._children:
            if isinstance(self._children[child], BFContainer):
                ret += "|" + self._children[child].pretty_print(indent + 1)
            else:
                ret += (
                    "|" + self._children[child].pretty_print(indent + 1) + f" : {child} " + "\n"
                )
        return ret


@register_type("length")
class BFLength(BFContainer):
    """Container prefixed by a length field covering its packed children."""

    TAGS = frozenset({"container", "length"})

    def __init__(self, field: "BFIntegerField", container: "BFContainer"):
        super().__init__()
        self._field = field
        self._children["_data"] = container

    def __getattr__(self, name):
        children = self.__dict__.get("_children")
        if children is not None and "_data" in children:
            data_children = children["_data"].__dict__.get("_children")
            if data_children is not None and name in data_children:
                return data_children[name]
        raise AttributeError(name)

    def __setattr__(self, name, obj):
        if isinstance(obj, BFBasicDataType) and not name.startswith("_"):
            if hasattr(type(self), name):
                raise BFTypeException(
                    f"{name!r} is reserved and cannot be used as a field name"
                )
            self.add("_data." + name, obj)
        else:
            super(BFContainer, self).__setattr__(name, obj)

    def pack(self) -> bytes:
        data: bytes = self._children["_data"].pack()
        self._field.value = len(data)
        return self._field.pack() + data

    @property  # type: ignore[misc]  # computed length is intentionally read-only
    def value(self) -> int:
        data = self._children["_data"].pack()
        self._field.value = len(data)
        return self._field.value

    def __str__(self) -> str:
        return self.pretty_print()

    def pretty_print(self, indent: int = 0) -> str:
        ret = " " * indent + f"+{self.name} length: 0x{self.value:0x}\n"
        data_children = self._children["_data"]._children
        for child in data_children:
            if isinstance(data_children[child], BFContainer):
                ret += "|" + data_children[child].pretty_print(indent + 1)
            else:
                ret += (
                    "|" + data_children[child].pretty_print(indent + 1) + f" : {child} " + "\n"
                )
        return ret


class ComputeContext:
    """Resolves referenced nodes for a computed field at pack time.

    Passed to a :class:`BFComputed` function, it turns nodes elsewhere in the
    structure into the bytes/value/length the computation needs. Targets are the
    actual node objects (not string paths), so references are validated eagerly
    and survive being embedded under a different parent.

    A future ``offset(node)`` — the position of a node within the packed output —
    slots in here without changing any of the following API.
    """

    def __init__(self, origin: "BFComputed"):
        self._origin = origin

    def bytes(self, *targets: "BFBasicDataType") -> bytes:
        """Packed bytes of one or more targets, concatenated in order."""
        return b"".join(target.pack() for target in targets)

    def value(self, target: "BFBasicDataType") -> Any:
        """The resolved value of a target field."""
        return target.value

    def length(self, target: "BFBasicDataType") -> int:
        """The packed length, in bytes, of a target."""
        return len(target.pack())

    def count(self, container: "BFContainer") -> int:
        """The number of direct children of a container."""
        return len(container.children)


@register_type("computed")
class BFComputed(BFBasicDataType):
    """A leaf field whose value is computed from other regions of the structure.

    ``fn(ctx)`` runs at pack time and returns the value stored in ``field``; the
    :class:`ComputeContext` ``ctx`` resolves nodes referenced *by object* into
    their bytes/value/length. This is a leaf — it holds no children — and can be
    placed anywhere in the tree.

    For the common cases prefer the helpers :func:`length_of`,
    :func:`checksum_of`, and :func:`count_of`; drop to ``BFComputed`` directly
    when you need custom arithmetic::

        frame.crc = BFComputed(BFUInt32(), lambda ctx: crc32(ctx.bytes(hdr, body)))

    Mutability
    ----------
    A computed field whose value only *describes* other data — a length — is a
    useful fuzzing target: injecting a value that disagrees with the data
    (length/data mismatch) exercises a whole bug class. Such a field is created
    ``mutable=True``: mutators may inject a value that *sticks* in the packed
    output (see :meth:`freeze`). Fields whose value must stay self-consistent —
    a checksum, an element count — are ``mutable=False`` (the default) and are
    excluded from mutation entirely.
    """

    TAGS = frozenset({"computed"})

    def __init__(
        self,
        field: "BFBasicDataType",
        fn: Callable[[ComputeContext], Any],
        *,
        mutable: bool = False,
    ):
        if not isinstance(field, BFBasicDataType):
            raise BFTypeException("field must be a BitFactory type")
        if not callable(fn):
            raise BFTypeException("fn must be callable")
        self._field = field
        self._fn = fn
        self._mutable = mutable
        self._frozen = False
        if mutable:
            # Let a mutator that reaches the storage field freeze recomputation.
            field._computed_owner = self

    @property
    def mutable(self) -> bool:
        """Whether this field may be mutated (its injected value sticks)."""
        return self._mutable

    def freeze(self, frozen: bool = True) -> None:
        """Pause/resume recomputation so an injected value survives a pack.

        Used by the mutation engine: while frozen, :meth:`pack` packs whatever
        value is currently in the storage field instead of recomputing it.
        """
        self._frozen = frozen

    def _compute(self) -> Any:
        return self._fn(ComputeContext(self))

    @property  # type: ignore[misc]  # computed value is intentionally read-only
    def value(self) -> Any:
        return self._compute()

    @property
    def length(self) -> int:
        return self._field.length

    def pack(self) -> bytes:
        if not self._frozen:
            self._field.value = self._compute()
        return self._field.pack()

    def __str__(self) -> str:
        return self.pretty_print()

    def pretty_print(self, indent: int = 0) -> str:
        val = self.value
        shown = f"0x{val:0x}" if isinstance(val, int) else repr(val)
        return " " * indent + "|= " + f"computed {shown}"


def _validate_targets(targets: "tuple[BFBasicDataType, ...]") -> None:
    for target in targets:
        if not isinstance(target, BFBasicDataType):
            raise BFTypeException("computed field targets must be BitFactory types")


def length_of(
    field: "BFBasicDataType", *targets: "BFBasicDataType", mutable: bool = True
) -> BFComputed:
    """A field holding the total packed length of ``targets`` (in bytes).

    Pass more than one target to count a range without wrapping it in a
    container: ``length_of(BFUInt16(), header, body)``.

    Length fields are ``mutable`` by default so fuzzers can inject a length that
    disagrees with the data; pass ``mutable=False`` to pin it.
    """
    _validate_targets(targets)
    return BFComputed(field, lambda ctx: len(ctx.bytes(*targets)), mutable=mutable)


def checksum_of(
    field: "BFBasicDataType",
    func: Callable[[bytes], Any],
    *targets: "BFBasicDataType",
    mutable: bool = False,
) -> BFComputed:
    """A field holding ``func`` applied to the packed bytes of ``targets``.

    ``func`` receives the concatenated bytes of every target in order, so a
    checksum can span a range of siblings directly. Checksums must stay
    consistent with their data, so they are ``mutable=False`` by default and are
    excluded from mutation.
    """
    if not callable(func):
        raise BFTypeException("func must be callable")
    _validate_targets(targets)
    return BFComputed(field, lambda ctx: func(ctx.bytes(*targets)), mutable=mutable)


def count_of(
    field: "BFBasicDataType", container: "BFContainer", *, mutable: bool = False
) -> BFComputed:
    """A field holding the number of direct children of ``container``."""
    if not isinstance(container, BFContainer):
        raise BFTypeException("count_of target must be a BFContainer")
    return BFComputed(field, lambda ctx: ctx.count(container), mutable=mutable)


def main():
    pass


if __name__ == "__main__":
    main()
