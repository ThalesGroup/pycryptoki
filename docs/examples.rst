Examples
========


--------------------------
Generating an RSA Key Pair
--------------------------

This example creates a 1024b RSA Key Pair.


   .. code-block:: python

       from pycryptoki.session_management import (c_initialize_ex, c_finalize_ex,
                                                  c_open_session_ex, c_close_session_ex,
                                                  login_ex)
       from pycryptoki.defines import CKM_RSA_PKCS_KEY_PAIR_GEN
       from pycryptoki.key_generator import c_generate_key_pair_ex

       c_initialize_ex()
       session = c_open_session_ex(0)      # 0 -> slot number
       login_ex(session, 0, 'userpin')     # 0 -> Slot number, 'userpin' -> token password

       # Templates are dictionaries in pycryptoki
       pub_template = {CKA_TOKEN: True,
                       CKA_PRIVATE: True,
                       CKA_MODIFIABLE: True,
                       CKA_ENCRYPT: True,
                       CKA_VERIFY: True,
                       CKA_WRAP: True,
                       CKA_MODULUS_BITS: 1024,  # long 0 - MAX_RSA_KEY_NBITS
                       CKA_PUBLIC_EXPONENT: 3,  # byte
                       CKA_LABEL: b"RSA Public Key"}
       priv_template = {CKA_TOKEN: True,
                        CKA_PRIVATE: True,
                        CKA_SENSITIVE: True,
                        CKA_MODIFIABLE: True,
                        CKA_EXTRACTABLE: True,
                        CKA_DECRYPT: True,
                        CKA_SIGN: True,
                        CKA_UNWRAP: True,
                        CKA_LABEL: b"RSA Private Key"}

       pub_key, priv_key = c_generate_key_pair_ex(session,
                                                  mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN,
                                                  pbkey_template=pub_template,
                                                  prkey_template=priv_template)

       c_close_session_ex(session)
       c_finalize_ex()


--------------------------------
Encrypting data with AES-CBC-PAD
--------------------------------

This example generates a 24-byte AES key, then encrypts some data
with that key using the AES-CBC-PAD mechanism.

   .. code-block:: python


       from pycryptoki.session_management import (c_initialize_ex, c_finalize_ex,
                                                  c_open_session_ex, c_close_session_ex,
                                                  login_ex)
       from pycryptoki.defines import (CKM_AES_KEY_GEN,
                                       CKA_LABEL,
                                       CKA_ENCRYPT,
                                       CKA_DECRYPT,
                                       CKA_TOKEN,
                                       CKA_CLASS,
                                       CKA_KEY_TYPE,
                                       CKK_AES,
                                       CKO_SECRET_KEY,
                                       CKA_SENSITIVE,
                                       CKA_WRAP,
                                       CKA_UNWRAP,
                                       CKA_DERIVE,
                                       CKA_VALUE_LEN,
                                       CKA_EXTRACTABLE,
                                       CKA_PRIVATE,
                                       CKM_AES_CBC_PAD)
       from pycryptoki.key_generator import c_generate_key_ex
       from pycryptoki.encryption import c_encrypt_ex
       from pycryptoki.conversions import to_bytestring, from_hex
       from pycryptoki.mechanism import Mechanism

       c_initialize_ex()
       session = c_open_session_ex(0)      # 0 = slot number
       login_ex(session, 0, 'userpin')        # 'userpin' = token password


       template = {CKA_LABEL: b"Sample AES Key",
                   CKA_ENCRYPT: True,
                   CKA_DECRYPT: True,
                   CKA_TOKEN: False,
                   CKA_CLASS: CKO_SECRET_KEY,
                   CKA_KEY_TYPE: CKK_AES,
                   CKA_SENSITIVE: True,
                   CKA_PRIVATE: True,
                   CKA_WRAP: True,
                   CKA_UNWRAP: True,
                   CKA_DERIVE: True,
                   CKA_VALUE_LEN: 24,
                   CKA_EXTRACTABLE: True,}
       aes_key = c_generate_key_ex(session, CKM_AES_KEY_GEN, template)

       # Data is in hex format here
       raw_data = "d0d77c63ab61e75a5fd4719fa77cc2de1d817efedcbd43e7663736007672e8c7"

       # Convert to raw bytes before passing into c_encrypt:
       data_to_encrypt = to_bytestring(from_hex(raw_data))


       # Note: this is *bad crypto practice*! DO NOT USE STATIC IVS!!
       mechanism = Mechanism(mech_type=CKM_AES_CBC_PAD,
                             params={"iv": list(range(16))})
       static_iv_encrypted_data = c_encrypt_ex(session, aes_key, data_to_encrypt, mechanism)

       c_close_session_ex(session)
       c_finalize_ex()


---------------------------------
Finding a key and decrypting Data
---------------------------------

This example follows from the previous one, except instead of generating a key,
we'll find one that was already used.


.. code-block:: python

       from pycryptoki.session_management import (c_initialize_ex, c_finalize_ex,
                                                  c_open_session_ex, c_close_session_ex,
                                                  login_ex)
       from pycryptoki.object_attr_lookup import c_find_objects_ex
       from pycryptoki.defines import (CKM_AES_KEY_GEN,
                                       CKA_LABEL,
                                       CKA_ENCRYPT,
                                       CKA_DECRYPT,
                                       CKA_TOKEN,
                                       CKA_CLASS,
                                       CKA_KEY_TYPE,
                                       CKK_AES,
                                       CKO_SECRET_KEY,
                                       CKA_SENSITIVE,
                                       CKA_WRAP,
                                       CKA_UNWRAP,
                                       CKA_DERIVE,
                                       CKA_VALUE_LEN,
                                       CKA_EXTRACTABLE,
                                       CKA_PRIVATE,
                                       CKM_AES_CBC_PAD)
       from pycryptoki.encryption import c_decrypt_ex
       from pycryptoki.conversions import to_bytestring, from_hex
       from pycryptoki.mechanism import Mechanism

       c_initialize_ex()
       session = c_open_session_ex(0)      # 0 = slot number
       login_ex(session, 0, 'userpin')        # 'userpin' = token password

       template = {CKA_LABEL: b"Sample AES key"}

       keys = c_find_objects_ex(session, template, 1)
       aes_key = keys.pop(0) # Use the first key found.

       # Data is in hex format here
       raw_data = "95e28bc6da451f3064d688dd283c5c43a5dd374cb21064df836e2970e1024c2448f129062aacbae3e45abd098b893346"

       # Convert to raw bytes before passing into c_decrypt:
       data_to_decrypt = to_bytestring(from_hex(raw_data))


       # Note: this is *bad crypto practice*! DO NOT USE STATIC IVS!!
       mechanism = Mechanism(mech_type=CKM_AES_CBC_PAD,
                             params={"iv": list(range(16))})
       original_data = c_decrypt_ex(session, aes_key, data_to_decrypt, mechanism)

       c_close_session_ex(session)
       c_finalize_ex()
