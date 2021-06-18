"""
Test creation of Attributes instance
"""

import pytest
import mock

from collections import defaultdict

from pycryptoki.attributes import Attributes, KEY_TRANSFORMS, c_struct_to_python

from hypothesis import given
from hypothesis.strategies import dictionaries, integers, one_of, none, just

from ctypes import c_ulong, sizeof

MAX_INT = 2 ** (sizeof(c_ulong) * 8) - 1


def new_xform(val, reverse=False):
    """
    Mock transformation to replace existing xforms in KEY_TRANSFORMS
    :param val: Any value.
    :param reverse: 'reverse' place holder for conversion methods
    :return: (1, 1)
    """
    if reverse:
        return 1
    return 1, 1


# Create mock dict w/ all xforms = 'new_xform'
mock_xform_dict = defaultdict(lambda: new_xform)
mock_xform_dict.update({key: new_xform for key in KEY_TRANSFORMS})


@pytest.fixture()
def setup_mock_dict():
    """ Fixture for creating dictionary of mockxforms """
    with mock.patch("pycryptoki.attributes.KEY_TRANSFORMS", new=mock_xform_dict):
        yield


@pytest.mark.usefixtures("setup_mock_dict")
class TestAttributes(object):
    def test_no_params(self):
        """ Create Attributes object without specifying any parameters """
        attr = Attributes()
        c_struct = attr.get_c_struct()
        assert isinstance(attr, Attributes)
        assert len(attr) == sizeof(c_struct) == 0

    @given(
        dictionaries(
            keys=integers(min_value=1, max_value=MAX_INT), values=none(), dict_class=Attributes
        )
    )
    def test_null_dictionary(self, test_dic):
        """
        Test creation of Attributes class.
        :param test_dic: Dictionary of random size, w/ all elements = None
        """
        res = test_dic.get_c_struct()
        for attr in res:
            assert attr.pValue is None
            assert attr.usValueLen == 0

        # Back to python dictionary
        py_dic = c_struct_to_python(res)
        assert test_dic == py_dic

    @given(
        dictionaries(
            keys=integers(min_value=1, max_value=MAX_INT), values=just(1), dict_class=Attributes
        )
    )
    def test_full_dictionary(self, test_dic):
        """
        Test creation of Attributes class.
        :param test_dic: Dicitonary of random size, w/ all elements = 1
        """
        res = test_dic.get_c_struct()
        for attr in res:
            assert attr.pValue == 1
            assert attr.usValueLen == 1

        # Back to python dictionary
        py_dic = c_struct_to_python(res)
        assert test_dic == py_dic

    @given(
        dictionaries(
            keys=integers(min_value=1, max_value=MAX_INT),
            dict_class=Attributes,
            values=one_of(just(1), none()),
        )
    )
    def test_rand_dictionary(self, test_dic):
        """
        Test creation of Attributes class.
        :param test_dic: Dictionary of random size, elements = 1 or None
        """
        # Iterate through dictionary and store keys w/ value = 1
        l = [key for key in test_dic if test_dic[key] == 1]

        res = test_dic.get_c_struct()
        for attr in res:
            if attr.type in l:
                assert attr.pValue == 1
                assert attr.usValueLen == 1
            else:
                assert attr.pValue is None
                assert attr.usValueLen == 0

        # Back to python dictionary
        py_dic = c_struct_to_python(res)
        assert test_dic == py_dic
