"""BitFactory exceptions.

All library errors derive from :class:`BFException`, so callers can catch every
BitFactory-specific failure with a single ``except BFException``.
"""


class BFException(Exception):
    """Base class for all BitFactory exceptions."""


class BFRangeException(BFException):
    """A value is out of range for its field."""


class BFEndianException(BFException):
    """An unknown or invalid byte order was supplied."""


class BFTypeException(BFException):
    """A value or field has an unexpected type."""
