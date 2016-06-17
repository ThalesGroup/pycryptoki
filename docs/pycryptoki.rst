Pycryptoki Package
==================

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

To use pycryptoki in LunaTAP on a remote client, use the daemon
:mod:`pycryptoki.daemon.rpyc_pycryptoki` as well as the client :mod:`pycryptoki.pycryptoki_client`.

.. toctree::
    :hidden:

    daemon <pycryptoki.daemon>


pycryptoki.cryptoki module
--------------------------

.. automodule:: pycryptoki.cryptoki
    :members:
    :undoc-members:


pycryptoki.cryptoki_helpers
---------------------------

.. automodule:: pycryptoki.cryptoki_helpers
    :members:
    :undoc-members:
    :show-inheritance:

pycryptoki.default_templates
----------------------------

.. automodule:: pycryptoki.default_templates
    :members:
    :undoc-members:
    :show-inheritance:

pycryptoki.defaults
-------------------

.. automodule:: pycryptoki.defaults
    :members:
    :undoc-members:
    :show-inheritance:


pycryptoki.dictionary_handling
------------------------------

.. automodule:: pycryptoki.dictionary_handling
    :members:
    :undoc-members:
    :show-inheritance:










