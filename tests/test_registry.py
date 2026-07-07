"""Tests for the type/mutator registry and extensibility surface."""

import pytest

from bitfactory import (
    BFContainer,
    BFEndian,
    BFIntegerBoundaryMutator,
    BFIntegerField,
    BFMutatable,
    get_type,
    list_types,
    register_type,
    types_with_tag,
)
from bitfactory import registry as reg
from bitfactory.registry import Registry


class TestRegistryCore:
    """Unit tests against an isolated Registry instance."""

    def test_register_and_get(self):
        r = Registry("type")

        @r.register(name="thing")
        class Thing:
            TAGS = frozenset({"custom"})

        assert r.get("thing") is Thing
        assert "thing" in r.names()

    def test_default_name_strips_bf_prefix(self):
        r = Registry("type")

        @r.register
        class BFWidget:
            TAGS = frozenset()

        assert r.get("widget") is BFWidget

    def test_tag_indexing(self):
        r = Registry("type")

        @r.register(name="a", tags=frozenset({"integer", "scalar"}))
        class A:
            pass

        @r.register(name="b", tags=frozenset({"buffer"}))
        class B:
            pass

        assert r.with_tag("integer") == [A]
        assert r.with_tag("buffer") == [B]
        assert r.with_tag("scalar") == [A]

    def test_duplicate_name_collision_raises(self):
        r = Registry("type")

        @r.register(name="dup")
        class First:
            pass

        with pytest.raises(ValueError, match="already registered"):

            @r.register(name="dup")
            class Second:
                pass

    def test_reregistering_same_object_is_noop(self):
        r = Registry("type")

        @r.register(name="same")
        class Same:
            pass

        # Registering the identical object under the same name is allowed.
        r.register(Same, name="same")
        assert r.get("same") is Same

    def test_unknown_name_raises_keyerror(self):
        r = Registry("type")
        with pytest.raises(KeyError, match="No type registered"):
            r.get("missing")


class TestBuiltinsRegistered:
    """The built-in types register themselves the same way third parties do."""

    def test_builtins_present(self):
        names = list_types()
        for expected in ("uint8", "sint8", "uint16", "uint32", "buffer", "container"):
            assert expected in names

    def test_lookup_builtin(self):
        assert get_type("uint16")().length == 2

    def test_integer_tag_discovery(self):
        integer_types = types_with_tag("integer")
        assert get_type("uint8") in integer_types
        assert get_type("sint32") in integer_types
        assert get_type("buffer") not in integer_types


# A third-party-style custom type defined entirely outside the library.
@register_type("uint24")
class BFUInt24(BFIntegerField):
    """Unsigned 24-bit integer contributed by a downstream user."""

    BYTE_WIDTH = 3
    SIGNED = False


class TestCustomType:
    """A user-defined width works for packing AND with existing mutators."""

    def test_custom_type_registered(self):
        assert get_type("uint24") is BFUInt24
        assert BFUInt24 in types_with_tag("integer")

    def test_custom_type_packs(self):
        assert BFUInt24(0xAABBCC, endian=BFEndian.BIG).pack() == b"\xaa\xbb\xcc"
        assert BFUInt24(0xAABBCC, endian=BFEndian.LITTLE).pack() == b"\xcc\xbb\xaa"

    def test_custom_type_tags(self):
        assert BFUInt24().tags == frozenset(
            {"integer", "scalar", "unsigned", "width:24"}
        )

    def test_custom_type_in_container(self):
        container = BFContainer()
        container.wide = BFUInt24(0x010203, endian=BFEndian.BIG)
        assert container.pack() == b"\x01\x02\x03"

    def test_existing_mutator_handles_custom_width(self):
        """The unmodified boundary mutator produces 24-bit-correct values."""
        mutator = BFIntegerBoundaryMutator()
        field = BFUInt24()
        assert mutator.can_mutate(field)

        values = [value for value, _desc in mutator.mutate(field)]
        # 24-bit unsigned max, derived from field.bit_width with no special case.
        assert 0xFFFFFF in values
        # Overflow past the 24-bit boundary is also generated.
        assert 0x1000000 in values

    def test_custom_type_auto_mutates_in_structure(self):
        container = BFContainer()
        container.wide = BFUInt24(0x000000, endian=BFEndian.BIG)
        mutatable = BFMutatable(container)
        mutatable.add_mutator(BFIntegerBoundaryMutator())

        results = list(mutatable)
        assert results, "expected mutations for the custom 24-bit field"
        # Every packed result is exactly 3 bytes wide.
        assert all(len(r.packed_data) == 3 for r in results)


class TestEntryPointDiscovery:
    """load_plugins() discovers types declared via entry points."""

    def test_entry_point_registers_type(self, monkeypatch):
        class FakeEntryPoint:
            name = "plugin_uint40"

            def load(self):
                @register_type("plugin_uint40")
                class BFUInt40(BFIntegerField):
                    BYTE_WIDTH = 5
                    SIGNED = False

                return BFUInt40

        def fake_iter(group):
            if group == reg.TYPE_ENTRY_POINT_GROUP:
                return [FakeEntryPoint()]
            return []

        monkeypatch.setattr(reg, "_iter_entry_points", fake_iter)
        try:
            reg.load_plugins()
            assert "plugin_uint40" in reg.list_types()
            cls = reg.get_type("plugin_uint40")
            assert cls(0x1122334455, endian=BFEndian.BIG).pack() == b"\x11\x22\x33\x44\x55"
        finally:
            reg.type_registry.unregister("plugin_uint40")

    def test_failing_entry_point_is_skipped(self, monkeypatch):
        class BadEntryPoint:
            name = "broken"

            def load(self):
                raise ImportError("simulated bad plugin")

        def fake_iter(group):
            if group == reg.TYPE_ENTRY_POINT_GROUP:
                return [BadEntryPoint()]
            return []

        monkeypatch.setattr(reg, "_iter_entry_points", fake_iter)
        # Must not raise despite the broken plugin.
        reg.load_plugins()
        assert "broken" not in reg.list_types()
