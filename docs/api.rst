API Reference
=============

There are some general guidelines to using pycryptoki:


    1. If you want to perform a PKCS11 operation as a multi-part operation, provide the input data
       as a list or a tuple.
    2. Data should always be passed into ``c_`` functions as raw byte data (bytestrings).
       Conversions are available to convert hex data or binary data to bytes at
       :ref:`pycryptoki.conversions<conversions>`
    3. Returned encrypted/decrypted data is always raw bytestrings.


.. toctree::

   Session/Token Management <api.sessions>
   Key Generation/Management <api.keys>
   Encryption/Decryption <api.encryption>
   Sign/Verify <api.sigver>
   Attributes <api.attributes>
   Mechanisms <api.mechanisms>
   Miscellaneous <api.misc>
   Helpers <api.helpers>
   Extensions <api.extensions>
   Bindings <api.bindings>
   RPYC Daemon <api.daemon>
