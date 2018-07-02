"""
Utilities for pycryptoki
"""
import logging
from _ctypes import pointer, POINTER
from ctypes import c_ulong, cast, create_string_buffer

from six import b, string_types

from .cryptoki import CK_CHAR
from .defines import CKR_OK

LOG = logging.getLogger(__name__)


class CException(Exception):
    """
    Raised from attempts at parsing ctypes!
    """
    pass


class AutoCArray(object):
    """
    An attempt to provide automatic resolution of C-style arrays.

    """

    def __init__(self, data=None, ctype=c_ulong, size=None):
        """
        Initialize the Array.

        If it's to be a target for Crypto operation output, you only need
        to specify the ctype (defaults to ULONG)

        Otherwise, you'll want to specify data and the ctype. Data can be a list-type
        object (this includes strings!). If it is a list, all objects in the list need to
        be compatible with your specified ctype.

        Size *always* needs to be a ctype in (c_ulong, c_uint)!

        You can specify a size at initialization time, if you know what the size will be.
        Otherwise, it will be set either by the crypto-op, defaulted to 0L, or set to the size
        of the given array.

        :param data: Data array should be initialized with. Needs to be string/list.
        :param ctype: Type of data the array should store (Default: CK_ULONG)
        :param size: Size of the array. PKCS#11 calls will init this for us, but you can also
        specify it manually.
        """
        self._array = None
        self._size = size
        self.ctype = ctype

        # name was just for logging.
        if data is not None:
            # Parse out any given data.
            if isinstance(data, (bytes, string_types)):
                self._array = create_string_buffer(b(data), len(data))
                self._size = c_ulong(len(data))
                self.ctype = CK_CHAR
            elif isinstance(data, list):
                self._array = (ctype * len(data))(*data)
                self._size = c_ulong(len(data))
            else:
                raise NotImplementedError("AutoCArray does not support given data type.")

    @property
    def array(self):
        """
        Allows for dynamic returning of data.

        If size is None, return None.
        If size is not None and internal array is None, return a pointer to a
        allocated memory of size self.ctype * self.size
        If size is not None, and internal array is not None, returna pointer to the
        allocated memory of the internal array.

        .. warning:: This will ONLY work properly if ``array`` is read before ``size``!
            You can assign to temporary values to work around this if the PKCS call requires the
            size first::

                array, len = autoarray.array, autoarray.size

            This is because after ``size`` is read, ``array`` is initialized to a C array of the
            given value.


        :return: pointer to the internal array.
        :rtype: POINTER
        """
        if self._size is None:
            # Return None, because this is the first time we've used this array.
            # We need to set the size first w/ a call.
            return None
        if self._array is None:
            # If we get to this point, we have a specified size, a ctype,
            # And our array is still none, but we're trying to access it.
            # Therefore, we go ahead & allocate the memory
            LOG.debug("Allocating %s buffer of size: %s", self.ctype, self._size.value)
            self._array = (self.ctype * self._size.value)()
        return cast(self._array, POINTER(self.ctype))

    @property
    def size(self):
        """
        Return a pointer to a c_ulong

        .. warning:: This will ONLY work properly if ``array`` is read before ``size``!
            You can assign to temporary values to work around this if the PKCS call requires the
            size first::

                array, len = autoarray.array, autoarray.size

            This is because after ``size`` is read, ``array`` is initialized to a C array of the
            given value.


        :return: Pointer to a CK_ULONG
        :rtype: pointer
        """
        if self._size is None:
            # Default size to a ulong.
            self._size = c_ulong()
        return pointer(self._size)

    def __len__(self):
        if self._array is not None:
            return len(self._array)
        else:
            return 0

    def __iter__(self):
        """
        Allow for iteration over contained data (you can't iterate over AutoCArray.array,
        as it is a pointer).
        """
        if self._array:
            for i in self._array:
                yield i

    def __str__(self):
        """
        Return a legible version of the array.
        """
        return "AutoCArray = ({ctype} * {size})({data})".format(ctype=self.ctype,
                                                                size=len(self),
                                                                data=self._array)


def refresh_c_arrays(retries=1):
    """
    Will re-run any Cryptoki function with an AutoCArray instance to automatically place the data
    into the array.

    This is so that it's easier to do cryptoki transforms::

        @refresh_c_arrays(retries=1)
        def closure_func():
            return C_PkcsFunction(slot, autoarray.array, autoarray.size)

        # Set up the closure, then run the PKCS11 function inside the closure.
        # This is so that the properties will work properly for both calls (rather
        # than being evaluated only once)

    :param func: Function to decorate.
    :return: closure.
    """

    def wrap(func):
        """
        Inner decorator.

        :param func: Original function decorated.
        :return:
        """

        def wrapped_func(*args, **kwargs):
            """
            Runs the wrapped function the given number of times,
            checking for failure.

            :param args:
            :param kwargs:
            :return:
            """
            tries = 0
            ret = None
            while tries <= retries:
                ret = func(*args, **kwargs)
                if ret != CKR_OK:
                    # Break early if one command failed.
                    return ret
                tries += 1
            return ret

        return wrapped_func

    return wrap


