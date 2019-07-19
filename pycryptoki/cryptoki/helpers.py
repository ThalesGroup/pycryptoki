"""
Contains some helper functions for creating C Bindings.
"""
import sys

IS_WINDOWS = "win" in sys.platform


def struct_def(struct, fields):
    """
    Defines the fields of a given structure as specified.

    Checks if the system is Windows first, as that would need a different struct packing.

    :param struct: Class definition of a struct.
    :param fields: List of tuples defining the fields (see ctypes docs)
    """
    if IS_WINDOWS:
        struct._pack_ = 1
    struct._fields_ = fields
