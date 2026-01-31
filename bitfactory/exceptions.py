"""BitFactory Exceptions"""


class BFRangeException(Exception):
    """BFRangeException

    Args:
        Exception: Out of range
    """

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class BFEndianException(Exception):
    """BFEndianException

    Args:
        Exception: BFEndianException
    """

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)


class BFTypeException(Exception):
    """BFTypeException

    Args:
        Exception: BFTypeException
    """

    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)
