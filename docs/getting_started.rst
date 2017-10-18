
Getting Started
===============

To use pycryptoki, you must have SafeNet LunaClient installed.

Installation
------------

Pycryptoki can be installed on any machine that has Python installed. Python versions >= 2.7
are supported.::

    pip install git+https://github.com/gemalto/pycryptoki


Pycryptoki will attempt to auto-locate the SafeNet Cryptoki shared library when pycryptoki
is first called. It will use the configuration files as defined by the LunaClient documentation to
determine which library to use.


Simple Example
--------------

This example will print out information about the given token slot.


    .. code-block:: python

        from pycryptoki.session_management import (c_initialize_ex,
                                                   c_get_info_ex,
                                                   get_firmware_version,
                                                   c_get_token_info_ex,
                                                   c_finalize_ex)


        c_initialize_ex()
        print("C_GetInfo: ")
        print("\n".join("\t{}: {}".format(x, y) for x, y in c_get_info_ex().items()))
        token_info = c_get_token_info_ex(0)
        print("C_GetTokenInfo:")
        print("\n".join("\t{}: {}".format(x, y) for x, y in token_info.items()))
        print("Firmware version: {}".format(get_firmware_version(0)))

        c_finalize_ex()
