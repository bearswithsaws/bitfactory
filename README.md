[![Coverage](https://coveralls.io/repos/github/bearswithsaws/bitfactory/badge.svg?branch=main)](https://coveralls.io/github/bearswithsaws/bitfactory?branch=main)
[![Pytest](https://github.com/bearswithsaws/bitfactory/actions/workflows/pytest.yml/badge.svg)](https://github.com/bearswithsaws/bitfactory/actions/workflows/pytest.yml)


# BitFactory

A module designed to facilitate quick and easy structured binary data creation allowing for the automatic adjustments of types such as lengths, checksums, etc of the modeled data.

# Install

`pip install bitfactory`

# Usage

An example for data strucured as follows:

- Type: Unsigned Byte
- Length: Unsigned Big-Endian Short that encompasses the Data and Checksum
- Data:
  - Unsigned 32 bit Int
  - Unsigned Byte
- Checksum: Unsigned Short that is calculated over the above Data portion only


```python
def csum(data: bytes) -> int:
    checksum = 0
    for value in data:
        checksum += value
    return checksum

data = BFContainer()
data.type = BFUInt8(1)
data.body = BFLength(BFUInt16(endian=BFEndian.BIG), BFContainer())
data.body.checksumed = BFContainer()
data.body.checksumed.data = BFUInt32(0xAABBCCDD)
data.body.checksumed.data2 = BFUInt8(10)
data.body.checksum = BFCallableRef(BFUInt16(), csum, "checksumed")
assert b"\x01\x00\x07\xdd\xcc\xbb\xaa\n\x18\x03" == data.pack()

>>> print(data)
+None
| |- Unsigned Byte 0x01 : type
| +body length: 0x7
|  +checksumed
|   |- Unsigned Long 0xAABBCCDD : data
|   |- Unsigned Byte 0x0A : data2
|  +checksum value: 0x318
```

# Writing your own type

BitFactory types are registerable, like layers in Scapy. You can define a new
field type in your own module and register it with a decorator — no need to fork
the library. Registered types work everywhere built-in types do: attribute-style
containers, packing, pretty-printing, and the mutator suite.

Integer types only need a width and signedness; everything else (masking,
endianness, boundaries, bit widths) is derived from those two attributes, so
arbitrary widths such as 24-bit or 64-bit work out of the box:

```python
from bitfactory import BFIntegerField, register_type

@register_type("uint24")
class BFUInt24(BFIntegerField):
    BYTE_WIDTH = 3
    SIGNED = False
```

That is enough for `BFUInt24` to pack correctly **and** to be understood by every
existing integer mutator (the boundary mutator will generate `MAX_UNSIGNED_24`,
overflow, etc. automatically — it reads `bit_width`/`signed` from the field
rather than switching on concrete classes).

Non-integer types implement the small field interface directly and advertise
their own `tags` so tooling can discover and dispatch on them:

```python
from bitfactory import BFBasicDataType, register_type

@register_type("macaddr", tags=frozenset({"address", "bytes"}))
class BFMacAddress(BFBasicDataType):
    TAGS = frozenset({"address", "bytes"})

    def __init__(self, value=b"\x00" * 6):
        self._value = value

    @property
    def value(self):
        return self._value

    def pack(self):
        return self._value

    def pretty_print(self, indent=0):
        pretty = ":".join(f"{b:02x}" for b in self._value)
        return " " * indent + "|- " + f"MAC {pretty}"
```

## Installable plugins (entry points)

To ship types (or mutators) in a separate package that registers automatically
when installed, declare entry points in your packaging metadata:

```toml
[project.entry-points."bitfactory.types"]
uint24  = "my_pkg.types:BFUInt24"
macaddr = "my_pkg.types:BFMacAddress"

[project.entry-points."bitfactory.mutators"]
my_mutator = "my_pkg.mutators:MyMutator"
```

`import bitfactory` calls `load_plugins()`, which discovers and registers every
type and mutator declared under these groups. Discovery helpers
(`list_types`, `get_type`, `types_with_tag`, and the mutator equivalents) let you
enumerate what is available.

See `examples/custom_type_plugin.py` for a runnable end-to-end demonstration.
