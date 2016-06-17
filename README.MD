## Pycryptoki

Pycryptoki is a python wrapper around the PKCS11 library.



## Installation

pip install git+https://github.com/gemalto/pycryptoki



## Tests

Unittests can be run on any environment using:
```
py.test tests/unittests
```

Functional tests require an HSM to test against, and will actively use the libCryptoki library.
These tests *will* factory reset the HSM! We're working on making it so that we don't have to do that,
but in the meantime, don't run this on a production HSM!

```
py.test tests/functional --slot=<slot_num>
```
