Frequent Issues
===============

.. contents::


Wrong data type
---------------

Any cryptographic function working on data (ex. ``c_encrypt``, ``c_unwrap``) will expect a
bytestring. A string object in Python2 is by default a *bytestring*, but in Python3 is a
*unicode* string.

For example::

     c_encrypt(session, key, "this is some test data", mechanism)

Will work in Python 2, but NOT Python 3. Instead, use the :ref:`pycryptoki.conversions<conversions>`
module to ensure that any data you pass into the cryptoki library is of the correct form.

Another 'gotcha' is that hex data represented as a string that is then used in an encrypt call would
result in 2x the length of expected data::

    from pycryptoki.conversions import to_bytestring, from_hex
    hex_data = "deadbeef"
    assert len(hex_data) == 8
    raw_data = list(from_hex(hex_data))
    assert len(raw_data) == 4
    print (raw_data)
    # Prints: [222, 173, 190, 239]

Another example::

    from pycryptoki.conversions import to_bytestring, from_hex
    some_hex_data = "06abde23df89"
    data_to_encrypt = to_bytestring(from_hex(some_hex_data))
    c_encrypt(session, key, data_to_encrypt, mechanism)

.. note::
    See this article for more details about the differences between unicode and bytestrings in
        python: http://lucumr.pocoo.org/2014/1/5/unicode-in-2-and-3/

Internal Initialization Vectors
-------------------------------

When you use an internal IV for AES mechanisms, the IV is appended to the cipher text. This needs to
be stripped off and used to create the mechanism for decryption::

    from pycryptoki.encryption import c_encrypt_ex

    data_to_encrypt = b"a" * 64
    mech = Mechanism(CKM_AES_KW,
                     params={"iv": []}) # Uses an internal IV

    enc_data = c_encrypt_ex(session, key, data_to_encrypt, mech)
    iv = enc_data[-16:] # Strip off the last 16 bytes of the encrypted data.
    decrypt_mech = Mechanism(CKM_AES_KW,
                             params={"iv": iv})
    decrypted_data = c_decrypt_ex(session, key, enc_data[:-16], decrypt_mech)


PKCS11 Calling Conventions
--------------------------

.. _Calling Convention: https://www.cryptsoft.com/pkcs11doc/v220/group__SEC__11__2__CONVENTIONS__FOR__FUNCTIONS__RETURNING__OUTPUT__IN__A__VARIABLE__LENGTH__BUFFER.html#SECTION_11_2

`The PKCS11 library has two main methods for returning data to the caller <https://www.cryptsoft.com/pkcs11doc/v220/group__SEC__11__2__CONVENTIONS__FOR__FUNCTIONS__RETURNING__OUTPUT__IN__A__VARIABLE__LENGTH__BUFFER.html#SECTION_11_2>`_:

    1. Allocate a large enough buffer for the resulting data and make the PKCS11 call with that buffer.
    2. Call the function with a NULL pointer for the buffer. The PKCS11 library will then place the
       required buffer size in ``*pulBufLen``.


Pycryptoki will let you perform either method for any function that returns data in a variable-length
buffer with the ``output_buffer`` keyword argument. This argument takes either an integer, or a list
of integers. The integer specifies the *size* of the buffer to use for the returned output. This means
if you use a very small integer, you could get back ``CKR_BUFFER_TOO_SMALL`` (and you could also
allocate a buffer that is incredibly large -- limited by the memory of your system).


By default, pycryptoki will use method #2 (querying the library for buffer size)::

    data = b"deadbeef"
    c_decrypt_ex(session, key, data, mechanism)


Will result in the raw underlying PKCS11 calls:


.. code-block:: none

    DEBUG: Cryptoki call: C_DecryptInit(8, <pycryptoki.cryptoki.CK_MECHANISM object at 0x7f693480c598>, c_ulong(26))
    DEBUG: Cryptoki call: C_Decrypt(8, <pycryptoki.cryptoki.LP_c_ubyte object at 0x7f69347df598>, c_ulong(2056), None, <pycryptoki.cryptoki.LP_c_ulong object at 0x7f69347dfbf8>)
    DEBUG: Allocating <class 'ctypes.c_ubyte'> buffer of size: 2048
    DEBUG: Cryptoki call: C_Decrypt(8, <pycryptoki.cryptoki.LP_c_ubyte object at 0x7f69347df598>, c_ulong(2056), <pycryptoki.cryptoki.LP_c_ubyte object at 0x7f693498c9d8>, <pycryptoki.cryptoki.LP_c_ulong object at 0x7f693498c840>)


.. note::
    ``None`` in python is the equivalent to ``NULL`` in C.

An example using a pre-allocated buffer::


    data = b"deadbeef"
    c_decrypt_ex(session, key, data, mechanism, output_buffer=0xffff)


And the resulting PKCS11 calls:

.. code-block:: none

    DEBUG: Cryptoki call: C_DecryptInit(8, <pycryptoki.cryptoki.CK_MECHANISM object at 0x7f693480c598>, c_ulong(26))
    DEBUG: Allocating <class 'ctypes.c_ubyte'> buffer of size: 2048
    DEBUG: Cryptoki call: C_Decrypt(8, <pycryptoki.cryptoki.LP_c_ubyte object at 0x7f69347df598>, c_ulong(2056), <pycryptoki.cryptoki.LP_c_ubyte object at 0x7f693498c9d8>, <pycryptoki.cryptoki.LP_c_ulong object at 0x7f693498c840>)


For multi-part operations, ``output_buffer`` should be a list of integers of equal size to the
number of parts in the operation::

    data = [b"a" * 8, b"b" * 8, b"c" * 8, b"d" * 8]
    output_buffer = [0xffff] * len(data)  # Equivalent to: [0xffff, 0xffff, 0xffff, 0xffff]
    c_encrypt_ex(session, key, data, mechanism, output_buffer=output_buffer)


For a multi-part operation that returns data in the ``C_*Final`` function, the output buffer will be
equivalent to the largest buffer size specified in the output_buffer list.
