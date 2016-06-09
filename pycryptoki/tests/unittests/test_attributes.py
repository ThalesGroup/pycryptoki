"""

"""
from _ctypes import POINTER
from ctypes import c_void_p, c_ulong, cast

from hypothesis import given
from hypothesis.strategies import integers
from ...attributes import to_long


class TestAttributes(object):

    @given(integers())
    def test_to_long(self, testval):
        pointer, len = to_long(testval)
        assert isinstance(pointer, c_void_p)
        assert isinstance(len, (long, int, c_ulong))
        finval = cast(pointer, POINTER(c_ulong)).contents
        assert finval >= 0
