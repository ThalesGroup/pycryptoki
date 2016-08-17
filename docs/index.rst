.. Pycryptoki documentation master file, created by
   sphinx-quickstart on Wed May 20 08:09:23 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Pycryptoki's documentation!
======================================

This package contains a python wrapper for our C PKCS11 libraries.
It provides automatic conversion to C types for the most commonly used functions.

You can use it similarly to how you would use the C version of the PKCS11 library::

    from pycryptoki.session_management import (c_initialize_ex, c_finalize_ex,
                                               c_open_session_ex, c_close_session_ex,
                                               login_ex)

    from pycryptoki.key_generator import c_generate_key_pair_ex

    c_initialize_ex()
    session = c_open_session_ex(SLOT)
    login_ex(session, 'userpin')

    pub_key_handle, priv_key_handle = c_generate_key_pair_ex(session)  # Will default to RSA PKCS templates

    c_close_session_ex(session)
    c_finalize_ex()


.. toctree::
   :maxdepth: 2
   :numbered:
   :includehidden:

   Session/Token Management <sessions>
   Key Generation/Management <keys>
   Encryption/Decryption <encryption>
   Sign/Verify <sigver>
   Attributes <attributes>
   Mechanisms <mechanisms>
   Miscellaneous <misc>
   RPYC Daemon <pycryptoki.daemon>




Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

