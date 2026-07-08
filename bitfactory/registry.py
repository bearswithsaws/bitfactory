"""Type and mutator registry for BitFactory.

This module lets third-party packages contribute custom field types and
mutators without modifying BitFactory itself. There are two ways to register:

1. In-process, using the :func:`register_type` / :func:`register_mutator`
   decorators (zero packaging required)::

       from bitfactory import BFIntegerField, register_type

       @register_type("uint24")
       class BFUInt24(BFIntegerField):
           BYTE_WIDTH = 3
           SIGNED = False

2. Via ``importlib.metadata`` entry points, so that simply ``pip install``-ing a
   plugin package makes its types available (the "scapy layer from another
   project" experience). A plugin declares entry points in its packaging
   metadata under these groups::

       [project.entry-points."bitfactory.types"]
       uint24 = "my_pkg.types:BFUInt24"

       [project.entry-points."bitfactory.mutators"]
       my_mutator = "my_pkg.mutators:MyMutator"

   Call :func:`load_plugins` (done automatically on ``import bitfactory``) to
   discover and register them.

Registered *tags* enable trait-based discovery (``types_with_tag("integer")``)
and mirror the tags a field instance exposes for mutator dispatch. When tags are
not passed explicitly they are derived from the registered class.
"""

from __future__ import annotations

import logging
from importlib import metadata
from typing import Callable, TypeVar, overload

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=type)

TYPE_ENTRY_POINT_GROUP = "bitfactory.types"
MUTATOR_ENTRY_POINT_GROUP = "bitfactory.mutators"


def _default_name(cls: type) -> str:
    """Derive a registry name from a class name (``BFUInt8`` -> ``uint8``)."""
    name = cls.__name__
    if name.startswith("BF"):
        name = name[2:]
    return name.lower()


def _resolve_tags(cls: type) -> frozenset[str]:
    """Best-effort read of a class's tags for discovery indexing.

    Tries a zero-arg instance's ``tags`` first (covers types whose tags depend on
    class-level metadata such as width/signedness), then a ``TAGS`` class
    attribute, then falls back to empty.
    """
    try:
        instance_tags = cls().tags  # type: ignore[call-arg]
        return frozenset(instance_tags)
    except Exception:  # noqa: BLE001 - discovery must never hard-fail
        pass
    return frozenset(getattr(cls, "TAGS", ()) or ())


class Registry:
    """A ``name -> class`` registry with tag indexing.

    Two independent instances back the public API: one for field types and one
    for mutators. Names are unique per registry; re-registering the same object
    under the same name is a no-op, but a name collision with a *different*
    object raises :class:`ValueError`.
    """

    def __init__(self, kind: str):
        self._kind = kind
        self._by_name: dict[str, type] = {}
        self._tags: dict[str, frozenset[str]] = {}

    def register(
        self,
        cls: T | None = None,
        *,
        name: str | None = None,
        tags: frozenset[str] | None = None,
    ) -> T | Callable[[T], T]:
        """Register ``cls``. Usable bare or parameterized as a decorator."""

        def _register(target: T) -> T:
            reg_name = name or _default_name(target)
            resolved_tags = _resolve_tags(target) if tags is None else frozenset(tags)
            existing = self._by_name.get(reg_name)
            if existing is not None and existing is not target:
                raise ValueError(
                    f"{self._kind} name {reg_name!r} is already registered to "
                    f"{existing.__module__}.{existing.__qualname__}"
                )
            self._by_name[reg_name] = target
            self._tags[reg_name] = resolved_tags
            logger.debug("Registered %s %r -> %r", self._kind, reg_name, target)
            return target

        if cls is None:
            return _register
        return _register(cls)

    def get(self, name: str) -> type:
        """Return the class registered under ``name`` or raise ``KeyError``."""
        try:
            return self._by_name[name]
        except KeyError as exc:
            raise KeyError(f"No {self._kind} registered under name {name!r}") from exc

    def names(self) -> list[str]:
        """Return all registered names, sorted."""
        return sorted(self._by_name)

    def items(self) -> dict[str, type]:
        """Return a copy of the ``name -> class`` mapping."""
        return dict(self._by_name)

    def with_tag(self, tag: str) -> list[type]:
        """Return all registered classes whose tags include ``tag``."""
        return [self._by_name[n] for n in sorted(self._by_name) if tag in self._tags[n]]

    def tags_for(self, name: str) -> frozenset[str]:
        """Return the discovery tags recorded for ``name``."""
        return self._tags.get(name, frozenset())

    def unregister(self, name: str) -> None:
        """Remove ``name`` if present (no error if absent)."""
        self._by_name.pop(name, None)
        self._tags.pop(name, None)

    def clear(self) -> None:
        """Drop all registrations (primarily for tests)."""
        self._by_name.clear()
        self._tags.clear()


# Two module-level registries back the public helpers below.
type_registry = Registry("type")
mutator_registry = Registry("mutator")


@overload
def register_type(name_or_cls: T, *, tags: frozenset[str] | None = None) -> T: ...


@overload
def register_type(
    name_or_cls: str | None = None, *, tags: frozenset[str] | None = None
) -> Callable[[T], T]: ...


def register_type(
    name_or_cls: str | T | None = None,
    *,
    tags: frozenset[str] | None = None,
) -> T | Callable[[T], T]:
    """Register a field type.

    Usable as ``@register_type``, ``@register_type("uint24")`` or
    ``@register_type("uint24", tags={"integer"})``.
    """
    if isinstance(name_or_cls, str) or name_or_cls is None:
        return type_registry.register(name=name_or_cls, tags=tags)
    return type_registry.register(name_or_cls, tags=tags)


@overload
def register_mutator(name_or_cls: T, *, tags: frozenset[str] | None = None) -> T: ...


@overload
def register_mutator(
    name_or_cls: str | None = None, *, tags: frozenset[str] | None = None
) -> Callable[[T], T]: ...


def register_mutator(
    name_or_cls: str | T | None = None,
    *,
    tags: frozenset[str] | None = None,
) -> T | Callable[[T], T]:
    """Register a mutator class (see :func:`register_type` for usage forms)."""
    if isinstance(name_or_cls, str) or name_or_cls is None:
        return mutator_registry.register(name=name_or_cls, tags=tags)
    return mutator_registry.register(name_or_cls, tags=tags)


def get_type(name: str) -> type:
    """Return the field type registered under ``name``."""
    return type_registry.get(name)


def get_mutator(name: str) -> type:
    """Return the mutator registered under ``name``."""
    return mutator_registry.get(name)


def list_types() -> list[str]:
    """Return the names of all registered field types."""
    return type_registry.names()


def list_mutators() -> list[str]:
    """Return the names of all registered mutators."""
    return mutator_registry.names()


def types_with_tag(tag: str) -> list[type]:
    """Return field types whose tags include ``tag`` (e.g. ``"integer"``)."""
    return type_registry.with_tag(tag)


def mutators_with_tag(tag: str) -> list[type]:
    """Return mutators whose tags include ``tag``."""
    return mutator_registry.with_tag(tag)


def _iter_entry_points(group: str):
    """Yield entry points for ``group`` across importlib.metadata versions."""
    try:
        # Python 3.10+ selectable API.
        yield from metadata.entry_points(group=group)  # type: ignore[call-arg]
    except TypeError:
        # Python 3.9 returns a dict keyed by group.
        yield from metadata.entry_points().get(group, [])  # type: ignore[attr-defined]


def load_plugins() -> None:
    """Discover and register types/mutators declared via entry points.

    Loading an entry point imports its target module; if that module used the
    ``register_*`` decorators, registration happens as an import side effect.
    Targets that are classes but were not self-registered are registered here
    under the entry-point name so that plain classes work too. Import failures
    are logged and skipped rather than breaking ``import bitfactory``.
    """
    for group, registry in (
        (TYPE_ENTRY_POINT_GROUP, type_registry),
        (MUTATOR_ENTRY_POINT_GROUP, mutator_registry),
    ):
        for entry_point in _iter_entry_points(group):
            try:
                obj = entry_point.load()
            except Exception:  # noqa: BLE001 - a bad plugin must not break import
                logger.exception("Failed to load %s entry point %r", group, entry_point.name)
                continue
            if isinstance(obj, type) and obj not in registry.items().values():
                registry.register(obj, name=entry_point.name)
