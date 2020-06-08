"""
Unit tests for AutoCArray in common_util.py
"""
from ctypes import *
from string import ascii_letters

import pytest
import sys
from hypothesis import given
from hypothesis.strategies import text, lists, sampled_from, integers
from six import b, binary_type

from pycryptoki.common_utils import AutoCArray

c_types = [
    c_short,
    c_ushort,
    c_long,
    c_ulong,
    c_int,
    c_uint,
    c_float,
    c_double,
    c_longlong,
    c_ulonglong,
    c_byte,
    c_ubyte,
    c_char,
    c_char_p,
    c_void_p,
    c_bool,
]

MAX_INT = 2 ** (sizeof(c_ulong) * 8) - 1


class TestAutoCArray(object):
    @pytest.mark.xfail(
        hasattr(sys, "pypy_version_info"), reason="Fails on Pypy w/ AssertionError: unknown shape g"
    )
    @given(sampled_from(c_types))
    def test_auto_c_array_empty(self, typ_val):
        """
        Initialize an empty array w/ elements of the given c_type.
        :param typ_val: randomly selected ctype
        """
        c_array = AutoCArray(ctype=typ_val)

        assert c_array.array is None
        assert c_array.size.contents.value == len(c_array) == 0
        assert c_array.ctype == typ_val

        if typ_val == c_char:
            assert c_array.array.contents.value == typ_val(b"\x00").value
        else:
            assert c_array.array.contents.value == typ_val(0).value

    @given(text(alphabet=ascii_letters))
    def test_auto_c_array_string(self, str_val):
        """
        Initialize an array from string.
        :param str_val: randomly generated string
        """
        c_array = AutoCArray(data=str_val)

        assert c_array.size.contents.value == len(c_array) == len(str_val)
        assert c_array.ctype == c_ubyte
        assert b"".join(c_array) == b(str_val)

    @given(lists(elements=integers(min_value=-128, max_value=127), min_size=1))
    def test_auto_c_array_byte_list(self, list_val):
        """
        Initalize an array from list of bytes.
        :param list_val: list of ints to be converted to c_byte's
        """
        list_val = [c_byte(x) for x in list_val]
        c_array = AutoCArray(data=list_val, ctype=c_byte)

        assert c_array.size.contents.value == len(c_array) == len(list_val)
        assert c_array.ctype == c_byte
        assert b"".join([bytes(c_byte(x)) for x in c_array]) == b"".join(
            [bytes(x) for x in list_val]
        )
        assert c_array.array[0] == cast(c_array.array, POINTER(c_byte)).contents.value

    @given(lists(elements=integers(min_value=0, max_value=256), min_size=1))
    def test_auto_c_array_ubyte_list(self, list_val):
        """
        Initalize an array from list of bytes.
        :param list_val: list of ints to be converted to c_ubyte's
        """
        list_val = [c_ubyte(x) for x in list_val]
        c_array = AutoCArray(data=list_val, ctype=c_ubyte)

        assert c_array.size.contents.value == len(c_array) == len(list_val)
        assert c_array.ctype == c_ubyte
        assert b"".join([bytes(c_ubyte(x)) for x in c_array]) == b"".join(
            [bytes(x) for x in list_val]
        )
        assert c_array.array[0] == cast(c_array.array, POINTER(c_ubyte)).contents.value

    @given(
        lists(
            elements=integers(min_value=int(-MAX_INT / 2), max_value=int(MAX_INT / 2)), min_size=1
        )
    )
    def test_auto_c_array_long_list(self, list_val):
        """
        Initalize an array from list of long's
        :param list_val: list of ints to be converted to c_long's
        """
        list_val = [c_long(x) for x in list_val]
        c_array = AutoCArray(data=list_val, ctype=c_long)

        assert c_array.size.contents.value == len(c_array) == len(list_val)
        assert c_array.ctype == c_long
        assert b"".join([bytes(c_long(x)) for x in c_array]) == b"".join(
            [bytes(x) for x in list_val]
        )
        assert c_array.array[0] == cast(c_array.array, POINTER(c_long)).contents.value

    @given(lists(elements=integers(min_value=0, max_value=MAX_INT), min_size=1))
    def test_auto_c_array_ulong_list(self, list_val):
        """
        Initalize an array from list of ulong's
        :param list_val: list of ints to be converted to c_ulong's
        """
        list_val = [c_ulong(x) for x in list_val]
        c_array = AutoCArray(data=list_val, ctype=c_ulong)

        assert c_array.size.contents.value == len(c_array) == len(list_val)
        assert c_array.ctype == c_ulong
        assert b"".join([bytes(c_ulong(x)) for x in c_array]) == b"".join(
            [bytes(x) for x in list_val]
        )
        assert c_array.array[0] == cast(c_array.array, POINTER(c_ulong)).contents.value

    @given(lists(elements=text(alphabet=ascii_letters, min_size=1, max_size=1), min_size=1))
    def test_auto_c_array_char_list(self, list_val):
        """
        Initalize an array from list of c_chars
        :param list_val: list of char to be converted to c_char's
        """
        list_val = [bytes(b(x)) for x in list_val]
        new_list_val = [c_char(x) for x in list_val]
        c_array = AutoCArray(data=new_list_val, ctype=c_char)

        assert c_array.size.contents.value == len(c_array) == len(list_val)
        assert c_array.ctype == c_char
        assert b"".join([x for x in c_array]) == b"".join(list_val)
        assert c_array.array[0] == cast(c_array.array, POINTER(c_char)).contents.value

    @given(list_val=lists(elements=integers(min_value=0, max_value=127), min_size=1))
    @pytest.mark.parametrize("test_type", [c_byte, c_ubyte, c_long, c_char])
    def test_auto_c_array_no_type_fail(self, list_val, test_type):
        """
        Attempt to initialize an array of 'test_type' without specifying the type. Should error
        :param list_val: Generated list, convert to 'test_type'
        :param test_type: c_types to test with
        """
        if test_type == c_char:
            new_list = [c_char(b(chr(x))) for x in list_val]
        else:
            new_list = [test_type(x) for x in list_val]

        with pytest.raises(TypeError):
            c_array = AutoCArray(data=new_list)
