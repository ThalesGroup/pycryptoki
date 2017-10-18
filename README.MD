## Pycryptoki
[![Doc Status](https://readthedocs.org/projects/pycryptoki/badge/?version=latest)](http://pycryptoki.readthedocs.io/en/latest/)

Pycryptoki is a python wrapper around the PKCS11 library.

## Documentation

Latest API documentation can be found on [readthedocs](http://pycryptoki.readthedocs.io/en/latest/index.html).


## Installation

pip install git+https://github.com/gemalto/pycryptoki

## Key Generation Example

```py
from pycryptoki.default_templates import *
from pycryptoki.defines import *
from pycryptoki.key_generator import *
from pycryptoki.session_management import *
from pycryptoki.encryption import *


c_initialize_ex()
auth_session = c_open_session_ex(0)   # HSM slot # in this example is 0
login_ex(auth_session, 0, 'userpin')  # 0 is still the slot number, ‘userpin’ should be replaced by your password (None if PED or no challenge)

# Get some default templates
# They are simple python dictionaries, and can be modified to suit needs.
pub_template, priv_template = get_default_key_pair_template(CKM_RSA_PKCS_KEY_PAIR_GEN)

# Modifying template would look like:
pub_template[CKA_LABEL] = "RSA PKCS Pub Key"
pub_template[CKA_MODULUS_BITS] = 2048   # 2048 key size

pubkey, privkey = c_generate_key_pair_ex(auth_session, CKM_RSA_PKCS_KEY_PAIR_GEN, pub_template, priv_template)
print("Generated Private key at %s and Public key at %s" % (privkey, pubkey))

c_logout_ex(auth_session)
c_close_session_ex(auth_session)
c_finalize_ex()
```
## Verbose logging

If you want to see what calls to the C library are being performed, set pycryptoki logging to `DEBUG`:

```py
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Tests

Test requirements can be installed via `pip install -r test_requirements.txt`.

Unittests can be run on any environment via:
```
py.test tests/unittests
```

Functional tests require an HSM to test against, and will actively test the integration
 with the libCryptoki library. This *will* create and destroy objects on the HSM, so don't run
  on a production HSM!

```
py.test tests/functional --slot=<slot_num> [--reset] [--password=<pwd>] [--copassword=<pwd>] [--user=<user>] [--loglevel=<level>]
```
