Pycryptoki
==========


.. toctree::
   :maxdepth: 4
   :includehidden:

   Getting Started      <getting_started>
   Examples             <examples>
   API Reference        <api>


Overview
--------

Pycryptoki is an open-source Python wrapper around Safenet's C PKCS11 library. Using python's ctypes library,
we can simplify memory management, and provide easy, pythonic access to a PKCS11 shared library.

This package contains a python wrapper for our C PKCS11 libraries.
It provides automatic conversion to C types for the most commonly used functions.

The primary function of pycryptoki is to *simplify* PKCS11 calls. Rather than needing to calculate
data sizes, buffers, or other low-level memory manipulation, you simply need to pass in data.

.. code-block:: python

   from pycryptoki.default_templates import *
   from pycryptoki.defines import *
   from pycryptoki.key_generator import *
   from pycryptoki.session_management import *


   c_initialize_ex()
   auth_session = c_open_session_ex(0)   # HSM slot # in this example is 0
   login_ex(auth_session, 0, 'userpin')  # 0 is still the slot number, ‘userpin’ should be replaced by your password (None if PED or no challenge)

   # Get some default templates
   # They are simple python dictionaries, and can be modified to suit needs.
   pub_template, priv_template = get_default_key_pair_template(CKM_RSA_PKCS_KEY_PAIR_GEN)

   # Modifying template would look like:
   pub_template[CKA_LABEL] = b"RSA PKCS Pub Key"
   pub_template[CKA_MODULUS_BITS] = 2048   # 2048 key size

   pubkey, privkey = c_generate_key_pair_ex(auth_session, CKM_RSA_PKCS_KEY_PAIR_GEN, pub_template, priv_template)
   print("Generated Private key at %s and Public key at %s" % (privkey, pubkey))

   c_logout_ex(auth_session)
   c_close_session_ex(auth_session)
   c_finalize_ex()



