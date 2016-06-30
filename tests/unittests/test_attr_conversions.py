"""
Unit tests for python/c type conversions
"""
import pytest
import logging

from hypothesis import given
from hypothesis.strategies import integers, floats, text, booleans, lists, dictionaries, one_of
from hypothesis.extra.datetime import dates

from _ctypes import POINTER
from ctypes import cast, c_void_p, c_ulong, sizeof

from pycryptoki.attributes import CK_ATTRIBUTE, CKA_CLASS, CK_BYTE, to_long, to_bool, to_char_array, \
                                  to_ck_date, to_byte_array, to_sub_attributes, Attributes, \
                                  convert_c_ubyte_array_to_string

from binascii import hexlify
from string import ascii_letters as letters

LOG = logging.getLogger(__name__)
MAX_INT = 2 ** (sizeof(c_ulong) * 8) - 1


class TestAttrConversions(object):

    def verify_c_type(self, pointer, leng):
        """
        Verifies that (pointer, leng) is a proper c type
        :param pointer: pointer to c data
        :param leng: length of c data
        """
        assert isinstance(pointer, c_void_p)
        assert isinstance(leng, (long, int, c_ulong))

    def create_ck_attr(self, pointer, leng):
        """
        Given (pointer, leng) creates a c attribute.
        :param pointer: pointer to c data
        :param leng: length of c data
        :return: c attribute
        """
        c_attr = CK_ATTRIBUTE(CKA_CLASS, pointer, leng)
        return c_attr

    def reverse_case(self, pointer, leng, func):
        """
        Perform the reverse operation of the given function on (pointer, leng)
        :param pointer: c pointer
        :param leng: data length
        :param func: function type
        :return: python type
        """
        c_attr = self.create_ck_attr(pointer, leng)
        return func(c_attr, reverse=True)

    def force_fail(self, val, func, error):
        """
        run val through func, assert that 'error' is raised
        :param val: data
        :param func: function
        :param error: expected error
        """
        with pytest.raises(error):
            pointer, leng = func(val)

    @given(integers(min_value=0, max_value=MAX_INT))
    def test_to_long(self, int_val):
        """
        to_long() with param:
        :param int_val: random integer >= 0
        """
        pointer, leng = to_long(int_val)
        self.verify_c_type(pointer, leng)

        # C type is unsigned integer. Assert result is positive.
        assert cast(pointer, POINTER(c_ulong)).contents >= 0

        py_long = self.reverse_case(pointer, leng, to_long)
        assert int_val == py_long

    @given(integers(max_value=-1))
    def test_to_long_neg_overflow(self, int_val):
        """
        test_to_long() with param:
        :param int_val: random negative int. Conversion will result in data loss.
        """
        pointer, leng = to_long(int_val)
        self.verify_c_type(pointer, leng)

        py_long = self.reverse_case(pointer, leng, to_long)
        LOG.debug("to_long() data loss: %s => %s", int_val, py_long)
        assert int_val != py_long

    @given(one_of(floats(), text()))
    def test_to_long_fail(self, fail_val):
        """
        to_long() with incompatible params:
        :param fail_val: random data of known incompatible types (floats, text)
        """
        self.force_fail(fail_val, to_long, TypeError)

    @given(booleans())
    def test_to_bool(self, bool_val):
        """
        to_bool() with param:
        :param bool_val: random boolean
        """
        pointer, leng = to_bool(bool_val)
        self.verify_c_type(pointer, leng)

        py_bool = self.reverse_case(pointer, leng, to_bool)
        assert bool_val == py_bool

    @given(integers(min_value=-100, max_value=100))
    def test_to_bool_int(self, int_val):
        """
        to_bool() with param:
        :param int_val: random int
        """
        pointer, leng = to_bool(int_val)
        self.verify_c_type(pointer, leng)

        py_bool = self.reverse_case(pointer, leng, to_bool)
        assert bool(int_val) == py_bool

    @given(one_of(floats(), text()))
    def test_to_bool_fail(self, fail_val):
        """
        to_bool() with incompatible param:
        :param fail_val: data of known incompatible type (floats, text)
        """
        self.force_fail(fail_val, to_bool, TypeError)

    @given(text(alphabet=letters))
    def test_to_char_array_string(self, txt_val):
        """
        to_char_array() with param:
        :param txt_val: random string
        """
        pointer, leng = to_char_array(str(txt_val))
        self.verify_c_type(pointer, leng)

        py_txt = self.reverse_case(pointer, leng, to_char_array)
        assert txt_val == py_txt

    @given(lists(elements=text(alphabet=letters, min_size=1, max_size=1), min_size=1))
    def test_to_char_array_list(self, list_val):
        """
        to_char_array() testing with param:
        :param list_val: random list of ascii strings
        """
        pointer, leng = to_char_array(list_val)
        self.verify_c_type(pointer, leng)

        py_txt = self.reverse_case(pointer, leng, to_char_array)
        assert "".join(list_val) == py_txt

    def test_to_char_array_fail_obj(self):
        """
        Trigger TypeError in to_char_array() with object as paramater.
        """
        self.force_fail(object(), to_char_array, TypeError)

    @given(dates(min_year=1900))
    def test_to_ck_date_string(self, date_val):
        """
        to_ck_date() with param:
        :param date_val: random date to be converted to date-string
        """
        date_string = str(date_val).replace("-", "")
        pointer, leng = to_ck_date(date_string)
        self.verify_c_type(pointer, leng)

        py_date = self.reverse_case(pointer, leng, to_ck_date)
        assert date_string == str(py_date)

    @given(dates(min_year=1900))
    def test_to_ck_date_dict(self, date_val):
        """
        to_ck_date() with param:
        :param date_val: random date to be converted to a dictionary.
        """
        date_dict = {'year': date_val.year, 'month': date_val.month, 'day': date_val.day}
        pointer, leng = to_ck_date(date_dict)
        self.verify_c_type(pointer, leng)

        py_date = self.reverse_case(pointer, leng, to_ck_date)
        assert (str(date_val).replace("-", "")) == py_date

    @given(dates(min_year=1900))
    def test_to_ck_date(self, date_val):
        """
        to_ck_date() with param:
        :param date_val: random date, kept as date object
        """
        pointer, leng = to_ck_date(date_val)
        self.verify_c_type(pointer, leng)

        py_date = self.reverse_case(pointer, leng, to_ck_date)
        assert str(date_val).replace("-", "") == py_date

    def test_to_ck_date_fail_obj(self):
        """
        Trigger TypeError in to_ck_date() with object as paramater.
        """
        self.force_fail(object(), to_ck_date, TypeError)

    @given(lists(elements=integers(min_value=0, max_value=255), min_size=1))
    def test_to_byte_array(self, list_val):
        """
        to_byte_array() with param:
        :param list_val: list of ints in range (0-255), convert to bytearray
        """
        b_array = bytearray(list_val)

        pointer, leng = to_byte_array(b_array)
        self.verify_c_type(pointer, leng)

        py_bytes = self.reverse_case(pointer, leng, to_byte_array)
        assert py_bytes == hexlify(b_array)

    @given(integers(min_value=0))
    def test_to_byte_array_int(self, int_val):
        """
        to_byte_array() with param:
        :param int_val: random positive integer
        """
        pointer, leng = to_byte_array(int_val)
        self.verify_c_type(pointer, leng)

        py_bytes = self.reverse_case(pointer, leng, to_byte_array)
        assert int(py_bytes, 16) == int_val

    @given(integers(max_value=-1))
    def test_to_byte_array_int_neg_overflow(self, int_val):
        """
        to_byte_array() with param:
        :param int_val: random int value. Will result in data loss
        """
        pointer, leng = to_byte_array(int_val)
        self.verify_c_type(pointer, leng)

        py_bytes = self.reverse_case(pointer, leng, to_byte_array)
        LOG.debug("to_byte_array() data loss: %s => %s", str(hex(int_val)), str(py_bytes))
        assert int(py_bytes, 16) != int_val

    @given(lists(elements=integers(min_value=0, max_value=255)))
    def test_to_byte_array_list(self, list_val):
        """
        to_byte_array() with param:
        :param list_val: randomly list of postive integers (within byte range).
        """
        pointer, leng = to_byte_array(list_val)
        self.verify_c_type(pointer, leng)

        py_bytes = self.reverse_case(pointer, leng, to_byte_array)

        # Create list from returned byte-string
        py_list = []
        for i in range(0, len(py_bytes), 2):
            py_list.append(int(py_bytes[i:i + 2], 16))

        assert py_list == list_val

    @given(lists(elements=integers(min_value=256), min_size=1))
    def test_to_byte_array_list_fail_big(self, list_val):
        """
        to_byte_array() with incompatible param:
        :param list_val: random list of integers > 256 -ValueError
        """
        with pytest.raises(ValueError):
            pointer, leng = to_byte_array(list_val)

    @given(lists(elements=integers(max_value=-1), min_size=1))
    def test_to_byte_array_list_fail_neg(self, list_val):
        """
        to_byte_array() with incompatible param:
        :param list_val: random list of negative integers. -ValueError
        """
        with pytest.raises(ValueError):
            pointer, leng = to_byte_array(list_val)

    def test_to_byte_array_fail_obj(self):
        """
        to_byte_array() with object param. -TypeError
        """
        self.force_fail(object(), to_byte_array, TypeError)

    @given(text(alphabet=letters, min_size=1))
    def test_to_byte_array_fail_str(self, txt_val):
        """
        to_byte_array() with incompatible param:
        :param txt_val: random text -TypeError
        """
        self.force_fail(txt_val, to_byte_array, TypeError)

    @given(integers(min_value=0))
    def test_to_byte_array_hexstring(self, int_val):
        """
        to_byte_array() with param:
        :param int_val: random integer to be converted to hex string.
        """
        hex_string = hex(int_val).replace("0x", "").replace("L", "")
        pointer, leng = to_byte_array(hex_string)
        self.verify_c_type(pointer, leng)

        py_bytes = self.reverse_case(pointer, leng, to_byte_array)
        assert int(py_bytes, 16) == int(hex_string, 16)

    @given(dictionaries(keys=integers(min_value=1, max_value=MAX_INT), dict_class=Attributes, values=booleans()))
    def test_to_sub_attributes(self, test_dic):
        """
        to_sub_attributes() with param
        :param test_dic: random dictionary of bools
        """
        pointer, leng = to_sub_attributes(test_dic)
        self.verify_c_type(pointer, leng)

    @given(integers())
    def test_to_sub_attributes_fail(self, int_val):
        """
        to_sub_attributes() with incompatible param:
        :param int_val: random integer
        """
        self.force_fail(int_val, to_sub_attributes, TypeError)

    @given(lists(elements=integers(min_value=0, max_value=255), min_size=1))
    def test_c_byte_array_to_string(self, list_val):
        b_array = bytearray(list_val)
        c_b_array = (CK_BYTE * len(b_array))(*b_array)

        str_result = convert_c_ubyte_array_to_string(c_b_array)
        assert str_result == hexlify(b_array)
