"""
Provide low-level conversions between common data types.

The ``from_xyz`` functions should all return an iterator over a list of integers,
representing the individual bytes in the passed-in value.

The ``to_xyz`` functions take in an iterable of integers and convert it to the specified type.



**Example 1**

    .. code-block:: python
        :caption: Convert a raw bytestring to hex

        raw_bytes = from_bytestring(b"Some test data")
        assert raw_bytes = [83, 111, 109, 101, 32, 116, 101, 115, 116, 32, 100, 97, 116, 97]

        hex_data = to_hex(from_bytestring(b"Some test data"))
        assert hex_data == b'536f6d6520746573742064617461'


**Example 2**

    .. code-block:: python
        :caption: Convert hex data to a raw bytestring

        bytestring_data = to_bytestring(from_hex(b'536f6d6520746573742064617461'))
        assert bytestring_data == b"Some test data"

        raw_bytes = list(from_hex(b'536f6d6520746573742064617461'))
        assert raw_bytes == [83, 111, 109, 101, 32, 116, 101, 115, 116, 32, 100, 97, 116, 97]


"""
from six import b


def _chunks(inval, chunk_size):
    """
    Split an iterable into chunks of the given size.

    :param inval: Iterable to be chunked.
    :param chunk_size: Size of chunks.
    :return: Iterator
    """
    for i in range(0, len(inval), chunk_size):
        yield inval[i : i + chunk_size]


def from_bytestring(ascii_):
    """
    Convert an iterable of strings into an iterable of integers.

    .. note:: For bytestrings on python3, this does effectively nothing, since
        iterating over a bytestring in python 3 will return integers.

    :param ascii_: String to convert
    :return: iterator
    """
    for c in ascii_:
        try:
            yield ord(c)
        except TypeError:
            yield c


def to_bytestring(ascii_):
    """
    Convert an iterable of integers into a bytestring.

    :param iterable ascii_: Iterable of integers
    :return: bytestring
    """
    return b("".join(chr(a) for a in ascii_))


def from_bin(bin_):
    """
    Convert a string-representation of binary into a list
    of integers.

    :param str bin_: String representation of binary data (ex: "10110111")
    :return: iterator over integers
    """
    for chunk in _chunks(bin_, 8):
        yield int(chunk, 2)


def to_bin(ascii_):
    """
    Convert an iterable of integers to a binary representation.

    :param iterable ascii_: iterable of integers
    :return: bytestring of the binary values
    """
    return b"".join(b("{:08b}".format(a)) for a in ascii_)


def from_hex(hex_):
    """
    Convert a hexademical string to an iterable of integers.

    :param str hex_: Hex string
    :return: Iterator
    """
    for chunk in _chunks(hex_, 2):
        yield int(chunk, 16)


def to_hex(ints):
    """
    Convert an iterable of integers to a hexadecimal string.

    :param iterable ints: Iterable of integers
    :return: bytestring representing the hex data.
    """
    return b"".join(b("{:02x}".format(a)) for a in ints)
