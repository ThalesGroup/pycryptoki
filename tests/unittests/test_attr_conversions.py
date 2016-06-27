"""
Contains unit tests for python -> C type conversion functions in attributes.py.
"""
import pytest
import binascii
import logging

from string import ascii_letters

from _ctypes import POINTER
from ctypes import cast, c_void_p, c_ulong, sizeof

from hypothesis import given
from hypothesis.strategies import integers, floats, text, booleans, lists, dictionaries
from hypothesis.extra.datetime import dates

from pycryptoki.attributes import CK_ATTRIBUTE, CKA_CLASS, to_long, to_bool, to_char_array, \
                                  to_ck_date, to_byte_array, to_sub_attributes, Attributes, \
                                  convert_c_ubyte_array_to_string

LOG = logging.getLogger(__name__)

# Max int value
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

        # Testing reverse case
        c_attr = self.create_ck_attr(pointer, leng)
        py_long = to_long(c_attr, reverse=True)

        assert int_val == py_long

    @given(integers(max_value=-1))
    def test_to_long_neg_overflow(self, int_val):
        """
        test_to_long() with param:
        :param int_val: random negative int. Conversion will result in data loss.
        """
        pointer, leng = to_long(int_val)
        self.verify_c_type(pointer, leng)

        # Testing reverse case
        c_attr = self.create_ck_attr(pointer, leng)
        py_long = to_long(c_attr, reverse=True)

        LOG.debug("to_long() data loss: %s => %s", int_val, py_long)
        assert int_val != py_long

    @given(floats())
    def test_to_long_fail_floats(self, flo_val):
        """
        to_long() with incompatible param:
        :param flo_val: random float -TypeError
        """
        with pytest.raises(TypeError):
            pointer, leng = to_long(flo_val)

    @given(text())
    def test_to_long_fail_str(self, txt_val):
        """
        to_long() with incompatible param:
        :param txt_val: random string -TypeError
        """
        with pytest.raises(TypeError):
            pointer, leng = to_long(txt_val)

    @given(booleans())
    def test_to_bool(self, bool_val):
        """
        to_bool() with param:
        :param bool_val: random boolean
        """
        pointer, leng = to_bool(bool_val)
        self.verify_c_type(pointer, leng)

        # Testing reverse case
        c_attr = self.create_ck_attr(pointer, leng)
        py_bool = to_bool(c_attr, reverse=True)
        assert bool_val == py_bool

    @given(integers(min_value=-100, max_value=100))
    def test_to_bool_int(self, int_val):
        """
        to_bool() with param:
        :param int_val: random int
        """
        pointer, leng = to_bool(int_val)
        self.verify_c_type(pointer, leng)

        # Testing reverse case
        c_attr = self.create_ck_attr(pointer, leng)
        py_bool = to_bool(c_attr, reverse=True)

        assert bool(int_val) == py_bool

    @given(floats())
    def test_to_bool_fail_floats(self, flo_val):
        """
        to_bool()  with incompatible param:
        :param flo_val: random float -TypeError
        """
        with pytest.raises(TypeError):
            pointer, leng = to_bool(flo_val)

    @given(text(alphabet=ascii_letters))
    def test_to_bool_fail_text(self, txt_val):
        """
        to_bool() with incompatible param:
        :param txt_val: random text -TypeError
        """
        with pytest.raises(TypeError):
            pointer, leng = to_bool(txt_val)

    @given(text(alphabet=ascii_letters))
    def test_to_char_array_string(self, txt_val):
        """
        to_char_array() with param:
        :param txt_val: random string
        """
        pointer, leng = to_char_array(str(txt_val))
        self.verify_c_type(pointer, leng)

        # Testing reverse case
        c_attr = self.create_ck_attr(pointer, leng)
        py_txt = to_char_array(c_attr, reverse=True)
        assert txt_val == py_txt

    @given(lists(elements=text(alphabet=ascii_letters, min_size=1, max_size=1), min_size=1))
    def test_to_char_array_list(self, list_val):
        """
        to_char_array() testing with param:
        :param list_val: random list of ascii strings
        """
        pointer, leng = to_char_array(list_val)
        self.verify_c_type(pointer, leng)

        # Testing reverse case
        c_attr = self.create_ck_attr(pointer, leng)
        py_txt = to_char_array(c_attr, reverse=True)

        assert "".join(list_val) == py_txt

    @given(booleans())
    def test_to_char_array_fail_bool(self, bool_val):
        """
        to_char_array() with incompatible parameter param:
        :param bool_val: random boolean -TypeError
        """
        with pytest.raises(TypeError):
            pointer, leng = to_char_array(bool_val)

    @given(dates(min_year=1900))
    def test_to_ck_date_string(self, date_val):
        """
        to_ck_date() with param:
        :param date_val: random date to be converted to date-string
        """
        date_string = str(date_val).replace("-", "")
        pointer, leng = to_ck_date(date_string)
        self.verify_c_type(pointer, leng)

        # Testing reverse case
        c_attr = self.create_ck_attr(pointer, leng)
        py_date = to_ck_date(c_attr, reverse=True)
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

        # Testing reverse case
        c_attr = self.create_ck_attr(pointer, leng)
        py_date = to_ck_date(c_attr, reverse=True)

        assert (str(date_val).replace("-", "")) == py_date

    @given(dates(min_year=1900))
    def test_to_ck_date(self, date_val):
        """
        to_ck_date() with param:
        :param date_val: random date, kept as date object
        """
        if date_val.year < 1900:
            with pytest.raises(ValueError):
                pointer, leng = to_ck_date(date_val)
                self.verify_c_type(pointer, leng)
        else:
            pointer, leng = to_ck_date(date_val)
            self.verify_c_type(pointer, leng)

            # Testing reverse case
            c_attr = self.create_ck_attr(pointer, leng)
            py_date = to_ck_date(c_attr, reverse=True)
            assert str(date_val).replace("-", "") == py_date

    @given(text())
    def test_to_ck_date_fail_str(self, txt_val):
        """
        to_ck_date() with incompatible param:
        :param txt_val: random text. -TypeError
        """
        with pytest.raises(TypeError):
            pointer, leng = to_ck_date(txt_val)

    @given(floats())
    def test_to_ck_date_fail_float(self, flo_val):
        """
        to_ck_date() with incompatible param:
        :param flo_val: random float -TypeError
        """
        with pytest.raises(TypeError):
            pointer, leng = to_ck_date(flo_val)

    @given(lists(elements=integers(min_value=0, max_value=255), min_size=1))
    def test_to_byte_array(self, list_val):
        """
        to_byte_array() with param:
        :param list_val: list of ints in range (0-255), convert to bytearray
        """
        # Generate the bytearray from list_val
        hex_list = [hex(x)[2:] for x in list_val]
        for i in range(len(hex_list)):
            if len(hex_list[i]) == 1:
                hex_list[i] = '0' + hex_list[i]
        b_array = bytearray(h.decode("hex") for h in hex_list)

        pointer, leng = to_byte_array(b_array)
        self.verify_c_type(pointer, leng)

        # Testing reverse case
        c_attr = self.create_ck_attr(pointer, leng)
        py_bytes = to_byte_array(c_attr, reverse=True)

        assert py_bytes == binascii.hexlify(b_array)

    @given(integers(min_value=0))
    def test_to_byte_array_int(self, int_val):
        """
        to_byte_array() with param:
        :param int_val: random positive integer
        """
        pointer, leng = to_byte_array(int_val)
        self.verify_c_type(pointer, leng)

        # Testing reverse case
        c_attr = self.create_ck_attr(pointer, leng)
        py_bytes = to_byte_array(c_attr, reverse=True)

        assert int(py_bytes, 16) == int_val

    @given(integers(max_value=-1))
    def test_to_byte_array_int_neg_overflow(self, int_val):
        """
        to_byte_array() with param:
        :param int_val: random int value. Will result in data loss
        """
        pointer, leng = to_byte_array(int_val)
        self.verify_c_type(pointer, leng)

        # Testing reverse case
        c_attr = self.create_ck_attr(pointer, leng)
        py_bytes = to_byte_array(c_attr, reverse=True)

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

        # Testing reverse case
        c_attr = self.create_ck_attr(pointer, leng)
        py_bytes = to_byte_array(c_attr, reverse=True)

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
        with pytest.raises(TypeError):
            pointer, leng = to_byte_array(object)

    @given(text(alphabet=ascii_letters, min_size=1))
    def test_to_byte_array_fail_str(self, txt_val):
        """
        to_byte_array() with incompatible param:
        :param txt_val: random text -TypeError
        :return:
        """
        with pytest.raises(TypeError):
            pointer, leng = to_byte_array(txt_val)

    @given(integers(min_value=0))
    def test_to_byte_array_hexstring(self, int_val):
        """
        to_byte_array() with param:
        :param int_val: random integer to be converted to hex string.
        """
        hex_string = hex(int_val).replace("0x", "").replace("L", "")
        pointer, leng = to_byte_array(hex_string)
        self.verify_c_type(pointer, leng)

        # Testing reverse case
        c_attr = self.create_ck_attr(pointer, leng)
        py_bytes = to_byte_array(c_attr, reverse=True)

        # Convert to int b/c of formating differences (0 != 00)
        assert int(py_bytes, 16) == int(hex_string, 16)

    @given(dictionaries(keys=integers(min_value=1, max_value=MAX_INT), dict_class=Attributes,
                        values=booleans()))
    def test_to_sub_attributes(self, test_dic):
        """
        to_sub_attributes() with param
        :param test_dic: random dictionary of bools
        :return:
        """
        pointer, leng = to_sub_attributes(test_dic)
        self.verify_c_type(pointer, leng)

        # TODO: Reverse case
