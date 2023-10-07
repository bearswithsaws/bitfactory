[![Coverage](https://coveralls.io/repos/github/bearswithsaws/bitfactory/badge.svg?branch=main)](https://coveralls.io/github/bearswithsaws/bitfactory)
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